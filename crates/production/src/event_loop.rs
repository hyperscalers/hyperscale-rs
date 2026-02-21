//! Pinned thread event loop for the production runner.
//!
//! [`NodeLoop`] runs on a dedicated `std::thread` pinned to core 0. It receives
//! events from three crossbeam channels with priority via `try_recv` cascade:
//!
//! ```text
//! timer_rx (priority 1) > callback_rx (priority 2) > consensus_rx (priority 3)
//! ```
//!
//! When nothing is ready, blocks on `crossbeam::select!` with a timeout derived
//! from the nearest batch deadline. Transaction statuses are written directly to
//! the shared `TransactionStatusCache` on the pinned thread, avoiding a channel
//! round-trip back to the async runtime.

use crate::rpc::state::TransactionStatusCache;
use crossbeam::channel::Receiver;
use hyperscale_core::{NodeInput, ProtocolEvent, TimerId};
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_metrics as metrics;
use hyperscale_network_libp2p::ProdNetwork;
use hyperscale_node::node_loop::{NodeLoop, TimerOp};
use hyperscale_storage_rocksdb::SharedStorage;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock as TokioRwLock;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Concrete NodeLoop type for the production runner.
///
/// Storage is `SharedStorage`, a newtype around `Arc<RocksDbStorage>`. This
/// allows the same underlying storage to be shared between the pinned NodeLoop
/// thread and async tasks (InboundRouter) via cheap Arc clones.
/// Certificate and transaction caches live inside NodeLoop itself.
pub type ProdNodeLoop = NodeLoop<SharedStorage, ProdNetwork, PooledDispatch>;

/// Configuration for the pinned event loop.
pub struct PinnedLoopConfig {
    /// Timer-fired events sender (for ProdTimerManager to send timer events).
    pub timer_tx: crossbeam::channel::Sender<NodeInput>,
    /// Timer-fired events (highest priority).
    pub timer_rx: Receiver<NodeInput>,
    /// Crypto/execution callback events + internal events.
    pub callback_rx: Receiver<NodeInput>,
    /// BFT consensus messages from network peers.
    pub consensus_rx: Receiver<NodeInput>,
    /// Graceful shutdown signal.
    pub shutdown_rx: Receiver<()>,
    /// Shared transaction status cache for RPC queries.
    /// Updated directly on the pinned thread after each step.
    pub tx_status_cache: Option<Arc<TokioRwLock<TransactionStatusCache>>>,
    /// Tokio runtime handle for spawning timer sleep tasks.
    pub tokio_handle: tokio::runtime::Handle,
    /// Timer ops from genesis initialization that need to be processed
    /// before the event loop starts (e.g. the initial ProposalTimer).
    pub initial_timer_ops: Vec<TimerOp>,
}

// ═══════════════════════════════════════════════════════════════════════
// ProdTimerManager — manages tokio-based timers on the pinned thread
// ═══════════════════════════════════════════════════════════════════════

/// Convert a TimerId to the corresponding Event.
fn timer_event(id: TimerId) -> NodeInput {
    match id {
        TimerId::Proposal => NodeInput::Protocol(ProtocolEvent::ProposalTimer),
        TimerId::Cleanup => NodeInput::Protocol(ProtocolEvent::CleanupTimer),
        TimerId::GlobalConsensus => NodeInput::Protocol(ProtocolEvent::GlobalConsensusTimer),
        TimerId::FetchTick => NodeInput::FetchTick,
    }
}

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
                    let _ = timer_tx.send(timer_event(timer_id));
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

/// Get wall-clock time as a Duration since UNIX epoch.
///
/// Used to set the state machine's logical clock before each step.
fn wall_clock_duration() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
}

/// Run the NodeLoop on a pinned thread.
///
/// This function blocks the calling thread until shutdown. It should be called
/// from a dedicated `std::thread::spawn` with core affinity set.
///
/// The event loop:
/// 1. Checks shutdown signal
/// 2. Sets wall-clock time on the state machine
/// 3. Tries to receive events in priority order (timer > callback > consensus)
/// 4. Falls back to `crossbeam::select!` with batch deadline timeout
/// 5. Processes the event via `NodeLoop::step()`
/// 6. Writes emitted statuses to tx_status_cache and records RPC latency
/// 7. Flushes expired batches
/// 8. Periodic metrics collection and JMT garbage collection
pub fn run_pinned_loop(mut node_loop: ProdNodeLoop, config: PinnedLoopConfig) {
    info!("Pinned event loop starting");

    let mut timer_mgr = ProdTimerManager::new(config.tokio_handle.clone(), config.timer_tx.clone());

    // Process timer ops from genesis initialization (e.g. ProposalTimer).
    for op in config.initial_timer_ops {
        timer_mgr.process_op(op);
    }

    let mut last_metrics = Instant::now();
    let mut last_gc = Instant::now();

    loop {
        // ── Shutdown check ──
        if config.shutdown_rx.try_recv().is_ok() {
            info!("Pinned event loop received shutdown signal");
            break;
        }

        // ── Set wall-clock time ──
        let now = wall_clock_duration();
        node_loop.set_time(now);

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
            let timeout = node_loop
                .nearest_batch_deadline()
                .map(|deadline| deadline.saturating_sub(now))
                .unwrap_or(DEFAULT_TIMEOUT);

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

        // ── Pre-step filtering ──
        // Skip gossip-received transactions that are already in terminal state
        // (avoids unnecessary validation batching for already-completed txs).
        let event = event.and_then(|event| {
            if let NodeInput::Protocol(ProtocolEvent::TransactionGossipReceived {
                ref tx, ..
            }) = event
            {
                if let Some(ref cache) = config.tx_status_cache {
                    if let Ok(guard) = cache.try_read() {
                        if guard.get(&tx.hash()).is_some_and(|c| c.status.is_final()) {
                            return None;
                        }
                    }
                }
            }
            Some(event)
        });

        // ── Process event ──
        if let Some(event) = event {
            let output = node_loop.step(event);

            // Process timer operations from this step.
            for op in output.timer_ops {
                timer_mgr.process_op(op);
            }

            // Write emitted statuses directly to the shared cache.
            if !output.emitted_statuses.is_empty() {
                if let Some(ref cache) = config.tx_status_cache {
                    if let Ok(mut guard) = cache.try_write() {
                        for (tx_hash, status) in &output.emitted_statuses {
                            guard.update(*tx_hash, status.clone());
                        }
                    }
                }
            }
        }

        // ── Flush expired batches ──
        node_loop.flush_expired_batches(wall_clock_duration());

        // ── Periodic metrics ──
        if last_metrics.elapsed() >= METRICS_INTERVAL {
            last_metrics = Instant::now();
            node_loop.collect_metrics();
            metrics::set_channel_depths(&hyperscale_metrics::ChannelDepths {
                callback: config.callback_rx.len(),
                consensus: config.consensus_rx.len(),
                validated_tx: 0,
                rpc_tx: 0,
                status: 0,
                sync_request: 0,
                tx_request: 0,
                cert_request: 0,
            });
        }

        // ── Periodic JMT GC ──
        if last_gc.elapsed() >= GC_INTERVAL {
            last_gc = Instant::now();
            let deleted = node_loop.storage().run_jmt_gc();
            if deleted > 0 {
                debug!(deleted, "JMT garbage collection completed");
            }
        }
    }

    info!("Pinned event loop exiting");
}

/// Spawn the NodeLoop on a dedicated pinned thread.
///
/// Returns a `JoinHandle` for the spawned thread. The caller should hold
/// on to this and join on shutdown.
pub fn spawn_pinned_loop(
    node_loop: ProdNodeLoop,
    config: PinnedLoopConfig,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("node-loop".to_string())
        .spawn(move || {
            // Try to pin to core 0
            if let Some(core_ids) = core_affinity::get_core_ids() {
                if let Some(&core_id) = core_ids.first() {
                    if core_affinity::set_for_current(core_id) {
                        info!(?core_id, "Pinned node-loop thread to core");
                    } else {
                        warn!("Failed to pin node-loop thread to core 0");
                    }
                }
            }

            run_pinned_loop(node_loop, config);
        })
        .expect("failed to spawn node-loop thread")
}
