//! Pinned thread event loop for the production runner.
//!
//! [`IoLoop`] runs on a dedicated `std::thread` pinned to core 0. It receives
//! events from three crossbeam channels with priority via `try_recv` cascade:
//!
//! ```text
//! timer_rx (priority 1) > callback_rx (priority 2) > consensus_rx (priority 3)
//! ```
//!
//! When nothing is ready, blocks on `crossbeam::select!` with a timeout derived
//! from the nearest batch deadline. Transaction statuses are written to
//! `IoLoop`'s internal `QuickCache`, shared with RPC handlers via `Arc`.

use crate::rpc::state::{MempoolSnapshot, NodeStatusState};
use crate::status::SyncStatus;
use arc_swap::ArcSwap;
use crossbeam::channel::Receiver;
use hyperscale_core::{NodeInput, TimerId};
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_metrics as metrics;
use hyperscale_network_libp2p::Libp2pNetwork;
use hyperscale_node::io_loop::{IoLoop, NodeStatusSnapshot, TimerOp};
use hyperscale_storage_rocksdb::SharedStorage;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Concrete `IoLoop` type for the production runner.
///
/// Storage is `SharedStorage`, a newtype around `Arc<RocksDbStorage>`.
/// This allows the same underlying storage to be shared between the pinned
/// `IoLoop` thread and async tasks (`InboundRouter`) via cheap Arc clones.
/// Certificate and transaction caches live inside `IoLoop` itself.
pub type ProdIoLoop = IoLoop<SharedStorage, Libp2pNetwork, PooledDispatch>;

/// Configuration for the pinned event loop.
pub struct PinnedLoopConfig {
    /// Timer-fired events sender (for `ProdTimerManager` to send timer events).
    pub timer_tx: crossbeam::channel::Sender<NodeInput>,
    /// Timer-fired events (highest priority).
    pub timer_rx: Receiver<NodeInput>,
    /// Crypto/execution callback events + internal events.
    pub callback_rx: Receiver<NodeInput>,
    /// BFT consensus messages from network peers.
    pub consensus_rx: Receiver<NodeInput>,
    /// Graceful shutdown signal.
    pub shutdown_rx: Receiver<()>,
    /// Tokio runtime handle for spawning timer sleep tasks.
    pub tokio_handle: tokio::runtime::Handle,
    /// Timer ops from genesis initialization that need to be processed
    /// before the event loop starts (e.g. the initial `ViewChange` timer).
    pub initial_timer_ops: Vec<TimerOp>,
    /// Optional shared `NodeStatusState` updated each metrics tick.
    pub rpc_status: Option<Arc<ArcSwap<NodeStatusState>>>,
    /// Optional shared `SyncStatus` updated each metrics tick.
    pub sync_status: Option<Arc<ArcSwap<SyncStatus>>>,
    /// Optional shared mempool snapshot updated each metrics tick.
    pub mempool_snapshot: Option<Arc<ArcSwap<MempoolSnapshot>>>,
}

// ═══════════════════════════════════════════════════════════════════════
// ProdTimerManager — manages tokio-based timers on the pinned thread
// ═══════════════════════════════════════════════════════════════════════

/// Manages tokio-based timers for the production pinned event loop.
///
/// Spawns async sleep tasks via the tokio handle that fire timer events
/// into the crossbeam timer channel. Replaces the former `ProdTimer` trait impl.
struct ProdTimerManager {
    tokio_handle: tokio::runtime::Handle,
    timer_tx: crossbeam::channel::Sender<NodeInput>,
    active: HashMap<TimerId, JoinHandle<()>>,
}

impl ProdTimerManager {
    fn new(
        tokio_handle: tokio::runtime::Handle,
        timer_tx: crossbeam::channel::Sender<NodeInput>,
    ) -> Self {
        Self {
            tokio_handle,
            timer_tx,
            active: HashMap::new(),
        }
    }

    fn process_op(&mut self, op: TimerOp) {
        match op {
            TimerOp::Set { id, duration } => {
                // Cancel existing timer with same ID.
                if let Some(handle) = self.active.remove(&id) {
                    handle.abort();
                }
                let timer_tx = self.timer_tx.clone();
                let timer_id = id.clone();
                let handle = self.tokio_handle.spawn(async move {
                    tokio::time::sleep(duration).await;
                    let _ = timer_tx.send(timer_id.into_event());
                });
                self.active.insert(id, handle);
            }
            TimerOp::Cancel { id } => {
                if let Some(handle) = self.active.remove(&id) {
                    handle.abort();
                }
            }
        }
    }
}

impl Drop for ProdTimerManager {
    fn drop(&mut self) {
        for (_, handle) in self.active.drain() {
            handle.abort();
        }
    }
}

/// Default metrics collection interval.
const METRICS_INTERVAL: Duration = Duration::from_secs(1);

/// Default JMT garbage collection interval.
const GC_INTERVAL: Duration = Duration::from_secs(30);

/// Fallback timeout when no batch deadlines are pending.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// Mint the `io_loop`'s monotonic local clock as a `LocalTimestamp` (ms
/// since UNIX epoch). Used to set the state machine's clock before each
/// step. We use `SystemTime` rather than process-start `Instant` because
/// the value sits next to `WeightedTimestamp` (also ms since UNIX epoch)
/// at the proposer-skew boundary; same epoch lets the comparison work
/// without unit conversion. NTP back-steps are absorbed by the saturating
/// arithmetic on `LocalTimestamp` — view-change timers can briefly fire
/// faster than expected after a step but will never panic.
fn wall_clock_local() -> hyperscale_types::LocalTimestamp {
    let ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    hyperscale_types::LocalTimestamp::from_millis(ms)
}

/// Push a [`NodeStatusSnapshot`] into the shared RPC state objects.
fn update_rpc_state(config: &PinnedLoopConfig, snapshot: &NodeStatusSnapshot) {
    if let Some(ref rpc_status) = config.rpc_status {
        let current = rpc_status.load();
        rpc_status.store(Arc::new(NodeStatusState {
            block_height: snapshot.committed_height.0,
            view: snapshot.view,
            state_root_hash: hex::encode(snapshot.state_root.as_bytes()),
            // Preserve fields set by other writers (runner sets connected_peers)
            validator_id: current.validator_id,
            shard: current.shard,
            num_shards: current.num_shards,
            connected_peers: current.connected_peers,
        }));
    }

    if let Some(ref sync_status) = config.sync_status {
        let current = sync_status.load();
        sync_status.store(Arc::new(SyncStatus {
            state: snapshot.sync.state.clone(),
            current_height: snapshot.sync.current_height,
            target_height: snapshot.sync.target_height,
            blocks_behind: snapshot.sync.blocks_behind,
            // Preserve sync_peers set by runner's collect_metrics
            sync_peers: current.sync_peers,
            pending_fetches: snapshot.sync.pending_fetches,
            queued_heights: snapshot.sync.queued_heights,
        }));
    }

    if let Some(ref mempool_snapshot) = config.mempool_snapshot {
        mempool_snapshot.store(Arc::new(MempoolSnapshot {
            pending_count: snapshot.mempool_pending,
            committed_count: snapshot.mempool_committed,
            executed_count: snapshot.mempool_executed,
            total_count: snapshot.mempool_total,
            accepting_rpc_transactions: snapshot.accepting_rpc_transactions,
            at_pending_limit: snapshot.at_pending_limit,
            remote_shard_in_flight: snapshot.remote_shard_in_flight.clone(),
            remote_congestion_threshold: snapshot.remote_congestion_threshold,
            updated_at: Some(Instant::now()),
        }));
    }
}

/// Run the `IoLoop` on a pinned thread.
///
/// This function blocks the calling thread until shutdown. It should be called
/// from a dedicated `std::thread::spawn` with core affinity set.
///
/// The event loop:
/// 1. Checks shutdown signal
/// 2. Sets wall-clock time on the state machine
/// 3. Tries to receive events in priority order (timer > callback > consensus)
/// 4. Falls back to `crossbeam::select!` with batch deadline timeout
/// 5. Processes the event via `IoLoop::step()`
/// 6. Writes emitted statuses to `tx_status_cache` and records RPC latency
/// 7. Flushes expired batches
/// 8. Periodic metrics collection and JMT garbage collection
pub fn run_pinned_loop(mut io_loop: ProdIoLoop, mut config: PinnedLoopConfig) {
    info!("Pinned event loop starting");

    let mut timer_mgr = ProdTimerManager::new(config.tokio_handle.clone(), config.timer_tx.clone());

    // Process timer ops from genesis initialization (e.g. ViewChange timer).
    for op in std::mem::take(&mut config.initial_timer_ops) {
        timer_mgr.process_op(op);
    }

    let mut last_metrics = Instant::now();
    let mut last_gc = Instant::now();
    let gc_in_flight = Arc::new(std::sync::atomic::AtomicBool::new(false));

    loop {
        // ── Shutdown check ──
        if config.shutdown_rx.try_recv().is_ok() {
            info!("Pinned event loop received shutdown signal");
            break;
        }

        // ── Set wall-clock time ──
        let now = wall_clock_local();
        io_loop.set_time(now);

        // ── Priority try_recv cascade ──
        let event = 'recv: {
            if let Ok(e) = config.timer_rx.try_recv() {
                break 'recv Some(e);
            }
            if let Ok(e) = config.callback_rx.try_recv() {
                break 'recv Some(e);
            }
            if let Ok(e) = config.consensus_rx.try_recv() {
                break 'recv Some(e);
            }

            // Nothing ready — block with timeout from nearest batch deadline
            let timeout = io_loop
                .nearest_batch_deadline()
                .map_or(DEFAULT_TIMEOUT, |deadline| deadline.saturating_sub(now));

            crossbeam::channel::select! {
                recv(config.shutdown_rx) -> _ => {
                    info!("Pinned event loop received shutdown signal (select)");
                    return;
                }
                recv(config.timer_rx) -> e => e.ok(),
                recv(config.callback_rx) -> e => e.ok(),
                recv(config.consensus_rx) -> e => e.ok(),
                default(timeout) => None,
            }
        };

        // ── Process event ──
        if let Some(event) = event {
            let output = io_loop.step(event);

            // Spawn block commit on tokio's blocking pool (pure I/O).
            if let Some(task) = output.commit_task {
                config.tokio_handle.spawn_blocking(task);
            }

            // Process timer operations from this step.
            for op in output.timer_ops {
                timer_mgr.process_op(op);
            }
        }

        // ── Flush expired batches ──
        io_loop.flush_expired_batches(wall_clock_local());

        // ── Periodic metrics + RPC status snapshot ──
        if last_metrics.elapsed() >= METRICS_INTERVAL {
            last_metrics = Instant::now();

            // Capture cheap snapshot on pinned thread, dispatch expensive
            // recording (RocksDB queries + prometheus calls) off-thread.
            let snapshot = io_loop.metrics_snapshot();
            let channel_depths = hyperscale_metrics::ChannelDepths {
                callback: config.callback_rx.len(),
                consensus: config.consensus_rx.len(),
                validated_tx: 0,
                rpc_tx: 0,
                status: 0,
                sync_request: 0,
                tx_request: 0,
                cert_request: 0,
            };
            let storage = io_loop.storage().clone();
            config.tokio_handle.spawn_blocking(move || {
                hyperscale_node::io_loop::record_metrics(snapshot, &*storage);
                metrics::set_channel_depths(&channel_depths);
            });

            // Push status snapshot to shared RPC state.
            update_rpc_state(&config, &io_loop.status_snapshot());
        }

        // ── Periodic JMT GC (off main thread) ──
        if !gc_in_flight.load(std::sync::atomic::Ordering::Relaxed)
            && last_gc.elapsed() >= GC_INTERVAL
        {
            last_gc = Instant::now();
            gc_in_flight.store(true, std::sync::atomic::Ordering::Relaxed);
            let storage = io_loop.storage().clone();
            let gc_flag = gc_in_flight.clone();
            config.tokio_handle.spawn_blocking(move || {
                let deleted = storage.run_jmt_gc();
                if deleted > 0 {
                    debug!(deleted, "JMT garbage collection completed");
                }
                let history_deleted = storage.run_state_history_gc();
                if history_deleted > 0 {
                    debug!(history_deleted, "State-history GC completed");
                }
                gc_flag.store(false, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }

    info!("Pinned event loop exiting");
}

/// Spawn the `IoLoop` on a dedicated pinned thread.
///
/// Returns a `JoinHandle` for the spawned thread. The caller should hold
/// on to this and join on shutdown.
pub fn spawn_pinned_loop(
    io_loop: ProdIoLoop,
    config: PinnedLoopConfig,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("io-loop".to_string())
        .spawn(move || {
            // Try to pin to core 0
            if let Some(core_ids) = core_affinity::get_core_ids() {
                if let Some(&core_id) = core_ids.first() {
                    if core_affinity::set_for_current(core_id) {
                        info!(?core_id, "Pinned io-loop thread to core");
                    } else {
                        warn!("Failed to pin io-loop thread to core 0");
                    }
                }
            }

            run_pinned_loop(io_loop, config);
        })
        .expect("failed to spawn io-loop thread")
}
