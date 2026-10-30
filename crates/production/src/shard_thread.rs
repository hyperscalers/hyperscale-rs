//! A hosted shard's pinned thread: its [`ShardLoop`], its timers, and the
//! channels it drains in priority order (timers, then signer changes,
//! then its two input lanes in turn), publishing the shard's RPC readouts
//! as it goes.
//!
//! [`ShardLoop`]: hyperscale_node::ShardLoop

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam::channel::{Receiver, Sender, bounded, never, unbounded};
use hex::encode as hex_encode;
use hyperscale_core::{ParticipationChange, TimerId};
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_metrics::set_shard_channel_depths;
use hyperscale_network_iroh::IrohNetwork;
use hyperscale_node::event::{
    HostEvent, NETWORK_LANE_CAPACITY, ShardInbox, StepOutput, TimerOp, TimerOwner, timer_event,
};
use hyperscale_node::{ShardLoop, ThreadShardLoop};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{MAX_UNSETTLED_TXS, ShardId, Signer, TxsInFlight, ValidatorId};
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::rpc::state::{RpcPublishers, VnodeMempoolSnapshot};
use crate::rpc::{VnodeMempoolStats, VnodeStatusEntry};
use crate::runner::wall_clock_local;
use crate::supervisor::SupervisorEvent;

/// Concrete `ShardLoop` type for the production runner.
pub type ProdShardLoop = ShardLoop<RocksDbShardStorage, IrohNetwork, PooledDispatch>;

/// Per-shard receivers driving a single shard's pinned thread. Built
/// during construction and consumed when [`ProductionRunner::run`]
/// hands the bundle to [`run_shard_loop`].
pub struct ShardChannels {
    pub(crate) timer_tx: Sender<HostEvent>,
    pub(crate) timer_rx: Receiver<HostEvent>,
    pub(crate) inputs: ShardInputs,
    pub(crate) shutdown_tx: Sender<()>,
    pub(crate) shutdown_rx: Receiver<()>,
    pub(crate) control_tx: Sender<ShardControl>,
    pub(crate) control_rx: Receiver<ShardControl>,
}

/// A change to a running shard loop's signers, sent by the supervisor to
/// the shard's thread.
pub enum ShardControl {
    /// Attach a validator to the loop's replica, signing with its key; the
    /// loop reports it as [`SupervisorEvent::Attached`].
    Attach(ValidatorId, Arc<dyn Signer>),
    /// Detach a validator from the loop's replica, which keeps running.
    Detach(ValidatorId),
}

impl ShardChannels {
    /// Allocate one shard's channels. Returns the shard's inbox alongside
    /// — it goes into the process-scoped sender map so callbacks, network
    /// handlers, and RPC fanout land on the shard's thread.
    pub(crate) fn new() -> (Self, ShardInbox) {
        let (timer_tx, timer_rx) = unbounded();
        let (inputs, inbox) = ShardInputs::new(NETWORK_LANE_CAPACITY);
        let (shutdown_tx, shutdown_rx) = unbounded();
        let (control_tx, control_rx) = unbounded();
        (
            Self {
                timer_tx,
                timer_rx,
                inputs,
                shutdown_tx,
                shutdown_rx,
                control_tx,
                control_rx,
            },
            inbox,
        )
    }
}

/// The receiving ends of a shard's [`ShardInbox`]: an unbounded internal
/// lane and a network lane bounded at the capacity it was built with.
///
/// The thread takes one input at a time, and while both lanes hold one it
/// takes them in turn, so neither lane waits on more than one input of
/// the other's, and each lane's inputs come out in the order they were
/// pushed.
pub struct ShardInputs {
    internal: Receiver<HostEvent>,
    network: Receiver<HostEvent>,
    /// Whether the network lane is next when both hold an input.
    network_next: bool,
}

/// The lane an input came off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    Internal,
    Network,
}

impl ShardInputs {
    fn new(network_capacity: usize) -> (Self, ShardInbox) {
        let (internal_tx, internal) = unbounded();
        let (network_tx, network) = bounded(network_capacity);
        (
            Self {
                internal,
                network,
                network_next: false,
            },
            ShardInbox::new(internal_tx, network_tx),
        )
    }

    /// The next queued input, if either lane holds one.
    fn try_recv(&mut self) -> Option<HostEvent> {
        let order = if self.network_next {
            [Lane::Network, Lane::Internal]
        } else {
            [Lane::Internal, Lane::Network]
        };
        order.into_iter().find_map(|lane| {
            let event = self.lane(lane).try_recv().ok()?;
            self.took(lane);
            Some(event)
        })
    }

    const fn lane(&self, lane: Lane) -> &Receiver<HostEvent> {
        match lane {
            Lane::Internal => &self.internal,
            Lane::Network => &self.network,
        }
    }

    /// Pass the turn to the other lane once `lane` gave an input.
    const fn took(&mut self, lane: Lane) {
        self.network_next = matches!(lane, Lane::Internal);
    }

    /// Settle what a blocking wait on `lane` returned. A lane whose
    /// senders are all gone is replaced by one that never fires, so the
    /// wait does not wake on it again.
    fn received(&mut self, lane: Lane, event: Option<HostEvent>) -> Option<HostEvent> {
        if let Some(event) = event {
            self.took(lane);
            return Some(event);
        }
        match lane {
            Lane::Internal => self.internal = never(),
            Lane::Network => self.network = never(),
        }
        None
    }
}

/// Manages tokio-based timers for one shard's pinned event loop.
///
/// Spawns async sleep tasks via the tokio handle that fire timer events
/// into the crossbeam timer channel. Every op a shard loop emits is the
/// loop's own.
struct ProdTimerManager {
    tokio_handle: TokioHandle,
    timer_tx: Sender<HostEvent>,
    active: BTreeMap<(TimerOwner, TimerId), JoinHandle<()>>,
}

impl ProdTimerManager {
    const fn new(tokio_handle: TokioHandle, timer_tx: Sender<HostEvent>) -> Self {
        Self {
            tokio_handle,
            timer_tx,
            active: BTreeMap::new(),
        }
    }

    fn process_op(&mut self, op: TimerOp) {
        match op {
            TimerOp::Set {
                owner,
                id,
                duration,
            } => {
                let key = (owner, id.clone());
                if let Some(handle) = self.active.remove(&key) {
                    handle.abort();
                }
                let timer_tx = self.timer_tx.clone();
                let timer_id = id;
                let handle = self.tokio_handle.spawn(async move {
                    sleep(duration).await;
                    let _ = timer_tx.send(timer_event(&timer_id, owner));
                });
                self.active.insert(key, handle);
            }
            TimerOp::Cancel { owner, id } => {
                if let Some(handle) = self.active.remove(&(owner, id)) {
                    handle.abort();
                }
            }
        }
    }
}

impl Drop for ProdTimerManager {
    fn drop(&mut self) {
        for handle in std::mem::take(&mut self.active).into_values() {
            handle.abort();
        }
    }
}

const METRICS_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// Per-shard pinned-thread configuration.
pub struct ShardLoopConfig {
    pub(crate) timer_tx: Sender<HostEvent>,
    pub(crate) timer_rx: Receiver<HostEvent>,
    pub(crate) inputs: ShardInputs,
    pub(crate) shutdown_rx: Receiver<()>,
    /// Signer changes from the supervisor.
    pub(crate) control_rx: Receiver<ShardControl>,
    pub(crate) tokio_handle: TokioHandle,
    pub(crate) initial_timer_ops: Vec<TimerOp>,
    /// Placement deltas emitted by this shard's replica, forwarded to
    /// the runner's reconfiguration loop.
    pub(crate) participation_tx: mpsc::UnboundedSender<ParticipationChange>,
    /// The supervisor's event channel, told of every signer the loop
    /// attaches.
    pub(crate) supervisor_tx: mpsc::UnboundedSender<SupervisorEvent>,
    /// Shared RPC publishers. Each shard's thread writes its own slots
    /// on the metrics tick (per-signer status entries, its sync-status
    /// key, and its signers' mempool snapshots); concurrent shards
    /// racing on the same `ArcSwap` lose at most one second of
    /// staleness on their slot.
    pub(crate) publishers: RpcPublishers,
}

/// Drive one shard's [`ShardLoop`] on its pinned thread. Blocks until
/// the shard's shutdown signal fires.
///
/// Priority cascade: `timer_rx` (scheduled view-change / cleanup /
/// fetch tick fires) before `control_rx` (signer changes) before the
/// shard's [`ShardInputs`] (off-thread results, fetch answers and RPC
/// fanout on the internal lane; inbound peer gossip and notifications on
/// the network lane), taken in turn. When all are empty the cascade
/// blocks on `select!` with a timeout drawn from the shard's nearest
/// batch deadline so the shard wakes precisely when its earliest
/// expiring batch is due.
///
/// However the thread exits, a panic included, the loop releases its
/// chain's registration with the host's beacon loop as it drops, before
/// the supervisor's join of this thread lets anything read its store as
/// replaced.
fn run_shard_loop(shard_loop: ProdShardLoop, config: ShardLoopConfig) {
    let mut shard_loop = ThreadShardLoop::from(shard_loop);
    drive_shard_loop(&mut shard_loop, config);
}

fn drive_shard_loop(shard_loop: &mut ProdShardLoop, mut config: ShardLoopConfig) {
    let shard = shard_loop.shard;
    info!(shard = ?shard, "Shard event loop starting");

    let mut timer_mgr = ProdTimerManager::new(config.tokio_handle.clone(), config.timer_tx.clone());
    for op in std::mem::take(&mut config.initial_timer_ops) {
        timer_mgr.process_op(op);
    }

    let mut last_metrics = Instant::now();

    loop {
        if config.shutdown_rx.try_recv().is_ok() {
            info!(shard = ?shard, "Shard event loop received shutdown signal");
            break;
        }

        let now = wall_clock_local();
        shard_loop.set_time(now);

        let event = 'recv: {
            if let Ok(e) = config.timer_rx.try_recv() {
                break 'recv Some(e);
            }
            if let Ok(control) = config.control_rx.try_recv() {
                apply_shard_control(shard_loop, &config, &mut timer_mgr, control);
                break 'recv None;
            }
            if let Some(e) = config.inputs.try_recv() {
                break 'recv Some(e);
            }

            let timeout = shard_loop
                .nearest_batch_deadline()
                .map_or(DEFAULT_TIMEOUT, |deadline| deadline.saturating_sub(now));

            let input = crossbeam::channel::select! {
                recv(config.shutdown_rx) -> _ => {
                    info!(shard = ?shard, "Shard event loop received shutdown signal (select)");
                    return;
                }
                recv(config.timer_rx) -> e => break 'recv e.ok(),
                recv(config.control_rx) -> control => {
                    if let Ok(control) = control {
                        apply_shard_control(shard_loop, &config, &mut timer_mgr, control);
                    }
                    break 'recv None;
                }
                recv(config.inputs.internal) -> e => (Lane::Internal, e.ok()),
                recv(config.inputs.network) -> e => (Lane::Network, e.ok()),
                default(timeout) => break 'recv None,
            };
            config.inputs.received(input.0, input.1)
        };

        if let Some(event) = event {
            let input = match event {
                HostEvent::Shard(s, input) if s == shard => input,
                HostEvent::Shard(other, _) => {
                    warn!(received_shard = ?other, this_shard = ?shard, "Dropping cross-shard event");
                    continue;
                }
                HostEvent::Process(_) => {
                    warn!(shard = ?shard, "Dropping process-scoped event on shard channel");
                    continue;
                }
                HostEvent::Beacon(_) => {
                    // Beacon-loop traffic runs on the beacon thread, never on
                    // a shard's thread.
                    warn!(shard = ?shard, "Dropping beacon-loop event on shard channel");
                    continue;
                }
            };
            // The wait may have outlasted the stamp taken before it: a
            // timer due now is handled at now, not before its deadline.
            shard_loop.set_time(wall_clock_local());
            let output = shard_loop.run_step(input);
            apply_step_output(shard, output, &config, &mut timer_mgr);
        }

        shard_loop.flush_expired_batches(wall_clock_local());

        // Per-shard prometheus emission + RPC status writes. Process-wide
        // pool and peer gauges are emitted from the runner's tokio tick.
        if last_metrics.elapsed() >= METRICS_INTERVAL {
            last_metrics = Instant::now();
            shard_loop.record_prometheus();
            set_shard_channel_depths(
                shard.inner(),
                config.inputs.internal.len(),
                config.inputs.network.len(),
                config.timer_rx.len(),
            );
            update_shard_rpc_state(shard_loop, &config);
        }
    }

    info!(shard = ?shard, "Shard event loop exiting");
}

/// Carry out one of the supervisor's signer changes on the shard's
/// thread.
fn apply_shard_control(
    shard_loop: &mut ProdShardLoop,
    config: &ShardLoopConfig,
    timer_mgr: &mut ProdTimerManager,
    control: ShardControl,
) {
    shard_loop.set_time(wall_clock_local());
    match control {
        ShardControl::Attach(validator, signer) => {
            let output = shard_loop.attach_signer(validator, signer);
            apply_step_output(shard_loop.shard, output, config, timer_mgr);
        }
        ShardControl::Detach(validator) => {
            if shard_loop.detach_signer(validator) {
                scrub_mempool_slot(config, validator);
            }
        }
    }
}

/// Hand one step's output to the timer manager, the runner and the
/// supervisor. Send failures mean the runner is shutting down.
fn apply_step_output(
    shard: ShardId,
    output: StepOutput,
    config: &ShardLoopConfig,
    timer_mgr: &mut ProdTimerManager,
) {
    for op in output.timer_ops {
        timer_mgr.process_op(op);
    }
    for change in output.participation_changes {
        let _ = config.participation_tx.send(change);
    }
    for validator in output.attached {
        let _ = config
            .supervisor_tx
            .send(SupervisorEvent::Attached { shard, validator });
    }
    for shard in output.reseats {
        let _ = config.supervisor_tx.send(SupervisorEvent::Reseat { shard });
    }
}

/// Drop a validator's mempool slot once it detaches from this shard's
/// replica. The slot is keyed by validator alone and written only by the
/// threads whose replica it is attached to, so a departed one would
/// otherwise hold a stale snapshot, and one still attached on another
/// shard republishes it on that shard's next tick.
fn scrub_mempool_slot(config: &ShardLoopConfig, validator: ValidatorId) {
    config.publishers.mempool.rcu(|current| {
        let mut updated = (**current).clone();
        updated.vnodes.remove(&validator.inner());
        Arc::new(updated)
    });
}

/// Write this shard's contribution into the shared RPC state. Each slot is
/// keyed by `shard_id.inner()`, and the writes go through `ArcSwap::rcu` so a
/// co-hosted shard's thread (or the supervisor's `scrub_rpc_state`)
/// interleaving on the same `ArcSwap` can't drop this shard's update — the
/// compare-and-retry re-applies it against the concurrent winner.
fn update_shard_rpc_state(shard_loop: &ProdShardLoop, config: &ShardLoopConfig) {
    let shard_key = shard_loop.shard.inner();

    // ── /status: one entry per attached signer ─────────────────────
    let state = shard_loop.replica();
    let mempool = state.mempool_coordinator();
    let pending = mempool.pending_count();
    let in_flight = state.shard_coordinator().committed_in_flight();
    config.publishers.node_status.rcu(|current| {
        let mut updated = (**current).clone();
        updated.vnodes.retain(|v| v.shard != shard_key);
        for validator in shard_loop.signers() {
            updated.vnodes.push(VnodeStatusEntry {
                validator_id: validator.inner(),
                shard: shard_key,
                block_height: state.shard_coordinator().committed_height().inner(),
                view: state.shard_coordinator().view().inner(),
                state_root_hash: hex_encode(state.last_committed_jmt_root().as_bytes()),
                mempool: VnodeMempoolStats {
                    pending_count: pending,
                    in_flight_count: in_flight,
                    total_count: mempool.len(),
                },
            });
        }
        updated.vnodes.sort_by_key(|v| (v.shard, v.validator_id));
        Arc::new(updated)
    });

    // ── /sync: per-shard block-sync state ──────────────────────────
    let sync_status = &config.publishers.sync_status;
    let block_sync = shard_loop.io.block_sync_status();
    sync_status.rcu(|current| {
        let mut updated = (**current).clone();
        updated.shards.insert(shard_key, block_sync.clone());
        Arc::new(updated)
    });

    // ── Mempool: the replica's snapshot under each attached signer,
    // feeding RPC submission backpressure.
    let mempool_snapshot = &config.publishers.mempool;
    let remote_congestion_threshold = TxsInFlight::new(MAX_UNSETTLED_TXS * 4 / 5);
    mempool_snapshot.rcu(|current| {
        let mut updated = (**current).clone();
        for validator in shard_loop.signers() {
            updated.vnodes.insert(
                validator.inner(),
                VnodeMempoolSnapshot {
                    accepting_rpc_transactions: in_flight < MAX_UNSETTLED_TXS,
                    at_pending_limit: mempool.at_pending_limit(),
                    remote_shard_in_flight: state
                        .remote_headers_coordinator()
                        .remote_shard_in_flight(),
                    remote_congestion_threshold,
                },
            );
        }
        Arc::new(updated)
    });
}

/// Spawn one shard's pinned thread. No core affinity — modern Linux
/// CFS keeps long-lived CPU-bound threads cache-warm without explicit
/// pinning, and the per-shard model already isolates each shard's
/// scheduling from the others.
pub fn spawn_shard_loop(
    shard_loop: ProdShardLoop,
    config: ShardLoopConfig,
) -> std::thread::JoinHandle<()> {
    let shard = shard_loop.shard;
    std::thread::Builder::new()
        .name(format!("shard-loop-{}", shard.inner()))
        .spawn(move || run_shard_loop(shard_loop, config))
        .expect("failed to spawn shard-loop thread")
}

#[cfg(test)]
mod tests {
    use crossbeam::channel::TrySendError;
    use hyperscale_node::event::{HostEvent, ShardScopedInput};
    use hyperscale_types::ShardId;

    use super::ShardInputs;

    /// An input tagged by the shard it names, so the order the lanes give
    /// inputs back in can be read off.
    fn input(tag: u64) -> HostEvent {
        HostEvent::shard(ShardId::leaf(8, tag), ShardScopedInput::FetchTick)
    }

    fn tag(event: &HostEvent) -> u64 {
        match event {
            HostEvent::Shard(shard, _) => shard.path(),
            _ => unreachable!("only shard inputs are pushed"),
        }
    }

    /// A full network lane refuses a push at once, and takes nothing from
    /// the internal lane: the thread takes the lanes in turn while both
    /// hold inputs, each lane in the order it was pushed, and drains the
    /// internal lane whole once the network lane is empty.
    #[test]
    fn a_full_network_lane_refuses_without_holding_back_the_internal_lane() {
        let (mut inputs, inbox) = ShardInputs::new(2);
        for tag in 0..4 {
            inbox
                .internal()
                .send(input(tag))
                .expect("internal lane open");
        }
        for tag in 10..12 {
            inbox
                .network()
                .try_send(input(tag))
                .expect("network lane has room");
        }
        assert!(
            matches!(
                inbox.network().try_send(input(12)),
                Err(TrySendError::Full(_))
            ),
            "a full network lane refuses the push",
        );
        inbox
            .internal()
            .send(input(4))
            .expect("the internal lane takes a push past a full network lane");

        let order: Vec<u64> = std::iter::from_fn(|| inputs.try_recv())
            .map(|event| tag(&event))
            .collect();
        assert_eq!(order, vec![0, 10, 1, 11, 2, 3, 4]);
    }
}
