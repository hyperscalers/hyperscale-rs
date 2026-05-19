//! Per-shard driver: state, scratch, step lifecycle, action handlers.
//!
//! [`ShardLoop`] is the active driver for one hosted shard — it owns the
//! shard's [`ShardIo`] (passive resource state), its `Vec<Vnode>`, per-step
//! scratch, and a cloned `Arc<ProcessIo>` for shared infrastructure.
//! `ShardLoop::step(input)` dispatches one [`ShardScopedInput`] to its
//! handler; same-shard vnodes see identical inbound events and produce
//! per-validator votes.
//!
//! The top-level [`NodeHost`] composes one `ShardLoop` per hosted shard
//! plus the shared `ProcessIo`. Cross-shard concerns (transaction
//! submission fan-out, fetch tick, batch flush coordination) live on
//! `NodeHost`; per-shard concerns live here.
//!
//! [`NodeHost`]: crate::host::NodeHost

mod actions;
mod fetch_io;
mod lifecycle;
mod metrics;
mod status;
mod step;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam::channel::Sender;
use hyperscale_core::{Action, ProtocolEvent, StateMachine, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::{PendingChain, Storage};
use hyperscale_types::{
    LocalTimestamp, RoutableTransaction, ShardGroupId, TopologySnapshot, TransactionStatus, TxHash,
};
pub use metrics::{MetricsSnapshot, ShardMetrics, VnodeMetrics, record_metrics};
pub use status::{NodeStatusSnapshot, ShardStatus, VnodeStatus};

use crate::batch_accumulator::BatchAccumulator;
pub use crate::event::{
    EventPriority, FetchFailureKind, ProcessScopedInput, ShardEvent, ShardScopedInput,
};
use crate::process_io::ProcessIo;
use crate::shard_io::ShardIo;
use crate::shard_io::block_commit::PreparedCommitMap;
use crate::shard_io::fetch::FetchInput;
use crate::shard_io::fetch::binding::{
    ExecCertBinding, FinalizedWaveBinding, LocalProvisionBinding, ProvisionBinding,
    TransactionBinding,
};
use crate::vnode::Vnode;

/// Lock-free shared topology snapshot for handler closures and dispatch.
///
/// Updated by the host when `Action::TopologyChanged` is processed.
/// Handler closures call `.load()` to get the current snapshot atomically.
pub type SharedTopologySnapshot = Arc<ArcSwap<TopologySnapshot>>;

/// Long-lived handles cloned into every delegated-action dispatch.
///
/// Wrapped in a single `Arc` so each dispatch pays one atomic-RMW for
/// the whole bundle. `topology_snapshot`, `event_sender`, and the
/// emitting vnode's signing key are not bundled — the snapshot needs
/// a fresh `load_full` per dispatch, the crossbeam `Sender` clone is
/// independent of these handles, and the signing key is per-vnode
/// (cloned separately at each dispatch site so the right validator
/// signs).
///
/// Shard-scoped handles (`pending_chain`, `prepared_commits`) live in
/// `per_shard`, keyed by the hosted shard id. Delegated handlers select
/// the right entry from the emitting vnode's shard.
pub(crate) struct DispatchHandles<S: Storage, N, E: Engine> {
    pub(crate) executor: E,
    pub(crate) network: Arc<N>,
    pub(crate) per_shard: HashMap<ShardGroupId, ShardDispatchHandles<S>>,
}

/// Per-shard subset of [`DispatchHandles`]. One entry per hosted shard.
pub(crate) struct ShardDispatchHandles<S: Storage> {
    pub(crate) pending_chain: Arc<PendingChain<S>>,
    pub(crate) prepared_commits: Arc<Mutex<PreparedCommitMap<S>>>,
}

// ═══════════════════════════════════════════════════════════════════════
// TimerOp — buffered timer operations for the runner
// ═══════════════════════════════════════════════════════════════════════

/// A timer operation buffered by `ShardLoop` for the runner to process.
///
/// `shard` is the hosted shard that owns the timer. Shard-scoped timers
/// (`ViewChange`, `Cleanup`) use it for both keying (so cross-shard
/// hosting doesn't collide `ViewChange` handles) and event routing
/// ([`timer_event`] produces a `ShardScopedInput::Protocol` for the right
/// shard). Process-scoped timers (`FetchTick`) push with a sentinel —
/// the firing path passes `shard` to [`timer_event`] which ignores it
/// for `FetchTick`.
#[derive(Debug, Clone)]
pub enum TimerOp {
    /// Set a timer to fire after `duration`.
    Set {
        /// Hosted shard that owns this timer.
        shard: ShardGroupId,
        /// Logical timer identifier (state-machine-side).
        id: TimerId,
        /// How long until the timer should fire.
        duration: Duration,
    },
    /// Cancel a previously set timer.
    Cancel {
        /// Hosted shard that owns this timer.
        shard: ShardGroupId,
        /// Logical timer identifier to cancel.
        id: TimerId,
    },
}

/// Translate a fired [`TimerId`] back into the [`ShardEvent`] the runner
/// pushes onto its event channel.
///
/// Shard-scoped timers tag the envelope with `shard` so the resulting
/// `ShardScopedInput::Protocol` routes to the right hosted shard;
/// `FetchTick` is process-scoped.
#[must_use]
pub fn timer_event(id: &TimerId, shard: ShardGroupId) -> ShardEvent {
    match id {
        TimerId::ViewChange => ShardEvent::protocol(shard, ProtocolEvent::ViewChangeTimer),
        TimerId::Cleanup => ShardEvent::protocol(shard, ProtocolEvent::CleanupTimer),
        TimerId::FetchTick => ShardEvent::process(ProcessScopedInput::FetchTick),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Event push helpers
// ═══════════════════════════════════════════════════════════════════════

/// Push a shard-scoped input into the event channel.
///
/// Off-thread closures and `ShardLoop` methods both use this to feed
/// results back to the next `step()`. The channel is unbounded; send
/// failure is silently ignored by design (the only failure mode is the
/// receiver having been dropped at shutdown, in which case there's
/// nothing to do).
pub(crate) fn push_shard_input(
    tx: &Sender<ShardEvent>,
    shard: ShardGroupId,
    input: ShardScopedInput,
) {
    let _ = tx.send(ShardEvent::shard(shard, input));
}

/// Push a [`ProtocolEvent`] (wrapped in
/// [`ShardScopedInput::Protocol`]) into the event channel.
/// The receiver fans the event across every hosted vnode in `shard`.
/// See [`push_shard_input`] for the drop-on-shutdown convention.
pub(crate) fn push_protocol_event(
    tx: &Sender<ShardEvent>,
    shard: ShardGroupId,
    event: ProtocolEvent,
) {
    let _ = tx.send(ShardEvent::protocol(shard, event));
}

// ═══════════════════════════════════════════════════════════════════════
// StepOutput — returned to the caller after processing an event
// ═══════════════════════════════════════════════════════════════════════

/// Output from processing a single event via `NodeHost::step()`.
///
/// Aggregates the per-step scratch from every hosted shard touched by
/// the event: emitted transaction statuses, timer operations, action
/// counts. Sync/fetch I/O and block-commit dispatch happen internally
/// via the `Network` and `Dispatch` traits — the runner only processes
/// emitted transaction statuses and timer operations.
pub struct StepOutput {
    /// Transaction status notifications emitted during this step.
    pub emitted_statuses: Vec<(TxHash, TransactionStatus)>,
    /// Number of actions generated by the state machine during this step.
    pub actions_generated: usize,
    /// Timer operations (set/cancel) to be processed by the runner.
    pub timer_ops: Vec<TimerOp>,
}

// ═══════════════════════════════════════════════════════════════════════
// ShardLoop — per-shard I/O state plus the vnodes that share it
// ═══════════════════════════════════════════════════════════════════════

/// Active per-shard driver: one hosted shard's [`ShardIo`] plus every
/// [`Vnode`] that participates in this shard's consensus, plus per-step
/// scratch and a shared `Arc<ProcessIo>`.
///
/// Same-shard vnodes share the [`ShardIo`] (one storage, one fetch host,
/// one mempool body store, etc.); cross-shard vnodes live in different
/// `ShardLoop`s. [`Self::step`] dispatches one [`ShardScopedInput`] to its
/// handler.
pub struct ShardLoop<S, N, D, E>
where
    S: Storage,
    D: Dispatch,
    E: Engine,
{
    /// Shard this loop drives. Mirrors the key in `NodeHost::shards`;
    /// held inline so methods on `ShardLoop` can self-identify without a
    /// parent-map lookup.
    pub shard: ShardGroupId,
    /// Process-scoped resources shared with every other hosted shard:
    /// network adapter, dispatch pool, tx validator, topology snapshot,
    /// dispatch handles, event sender. Cloned `Arc` so off-thread
    /// closures spawned from this loop's handlers can capture it cheaply.
    pub(crate) process: Arc<ProcessIo<S, N, D, E>>,
    /// Per-shard I/O state shared by every vnode in `vnodes`.
    pub io: ShardIo<S>,
    /// Vnodes participating in this shard's consensus. Driven in order
    /// during each `step()` iteration; same-shard vnodes see identical
    /// inbound events and produce per-validator votes.
    pub vnodes: Vec<Vnode>,
    /// Cached wall-clock time for this shard. Set by the runner via
    /// `NodeHost::set_time` (which propagates to every hosted shard);
    /// read by per-vnode `state.handle(now, _)` calls and by helpers
    /// that need a single consistent stamp across an action burst.
    pub now: LocalTimestamp,
    /// Per-step scratch: timer set/cancel operations emitted during the
    /// step. Cleared at step entry; drained into the returned
    /// [`StepOutput`] for the runner to translate into timer-driver
    /// calls.
    pub pending_timer_ops: Vec<TimerOp>,
    /// Per-step scratch: `(tx_hash, status)` pairs emitted via
    /// `Action::EmitTransactionStatus`. Drained into [`StepOutput`].
    pub emitted_statuses: Vec<(TxHash, TransactionStatus)>,
    /// Per-step scratch: count of actions this shard's vnodes produced
    /// during the step. Drained into [`StepOutput`] for the runner's
    /// metrics; reset at step entry.
    pub actions_generated: usize,
    /// Per-destination-shard outbound `TransactionGossip` accumulators.
    /// This shard acts as the "source" — locally-submitted or validated
    /// transactions are appended here keyed by destination, each batch
    /// fills until its count cap or time window expires, then flushes
    /// as a single batched gossip message published to the destination
    /// shard's topic.
    pub outbound_gossip_batches: BTreeMap<ShardGroupId, BatchAccumulator<Arc<RoutableTransaction>>>,
    /// Size cap for new tx-gossip accumulators.
    pub tx_gossip_max: usize,
    /// Time window for new tx-gossip accumulators.
    pub tx_gossip_window: Duration,
}

impl<S, N, D, E> ShardLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Access the vnode at `vnode_idx` within this shard's group.
    ///
    /// # Panics
    /// Panics if `vnode_idx` is out of range.
    pub(crate) fn vnode(&self, vnode_idx: usize) -> &Vnode {
        &self.vnodes[vnode_idx]
    }

    /// Mutably access the vnode at `vnode_idx` within this shard's group.
    ///
    /// # Panics
    /// Panics if `vnode_idx` is out of range.
    pub(crate) fn vnode_mut(&mut self, vnode_idx: usize) -> &mut Vnode {
        &mut self.vnodes[vnode_idx]
    }

    /// Dispatch a [`ShardScopedInput`] to its handler. Does NOT clear or
    /// drain per-step scratch — the caller (typically [`NodeHost::step`])
    /// manages the scratch lifecycle so cross-shard
    /// `update_fetch_tick_timer` pushes aggregate cleanly.
    ///
    /// [`NodeHost::step`]: crate::host::NodeHost::step
    pub(crate) fn step(&mut self, input: ShardScopedInput) {
        match input {
            // ── Transaction validation pipeline ────────────────────────
            ShardScopedInput::TransactionGossipReceived { tx } => {
                self.handle_gossip_received_tx_for_validation(tx);
            }
            ShardScopedInput::AdmitTransaction { tx } => {
                self.handle_admit_transaction(tx);
            }
            ShardScopedInput::AdmitAndGossipTransaction { tx, touched_shards } => {
                self.handle_admit_and_gossip_transaction(tx, &touched_shards);
            }
            ShardScopedInput::TransactionValidated { tx } => {
                self.handle_transaction_validated(tx);
            }
            ShardScopedInput::TransactionValidationsFailed { hashes } => {
                self.handle_transaction_validations_failed(&hashes);
            }
            ShardScopedInput::Protocol(event) => match *event {
                ProtocolEvent::BlockPersisted { height } => self.handle_block_persisted(height),
                other => self.handle_protocol_passthrough(other),
            },

            // ── Sync protocol ──────────────────────────────────────────
            ShardScopedInput::BlockSyncResponseReceived { height, block } => {
                self.handle_block_sync_response_received(height, block);
            }
            ShardScopedInput::BlockSyncFetchFailed { height, kind } => {
                self.handle_block_sync_fetch_failed(height, kind);
            }
            ShardScopedInput::SyncBlockValidated { height, certified } => {
                self.handle_sync_block_validated(height, *certified);
            }
            ShardScopedInput::SyncBlockValidationFailed { height, reason } => {
                self.handle_sync_block_validation_failed(height, reason);
            }
            ShardScopedInput::RemoteHeadersResponseReceived {
                source_shard,
                from_height,
                count,
                headers,
            } => {
                self.handle_remote_headers_response_received(
                    source_shard,
                    from_height,
                    count,
                    headers,
                );
            }
            ShardScopedInput::RemoteHeadersFetchFailed {
                source_shard,
                from_height,
                count,
                kind,
            } => {
                self.handle_remote_headers_fetch_failed(source_shard, from_height, count, kind);
            }

            // ── Fetch protocol ─────────────────────────────────────────
            ShardScopedInput::TransactionsFetchFailed { hashes } => {
                self.drive_fetch::<TransactionBinding>(FetchInput::Failed { ids: hashes });
            }
            ShardScopedInput::ProvisionsFetchFailed {
                source_shard,
                block_height,
            } => {
                let local_shard = self.shard;
                self.drive_fetch::<ProvisionBinding>(FetchInput::Failed {
                    ids: vec![(source_shard, local_shard, block_height)],
                });
            }
            ShardScopedInput::ExecCertFetchFailed { hashes } => {
                self.drive_fetch::<ExecCertBinding>(FetchInput::Failed { ids: hashes });
            }
            ShardScopedInput::LocalProvisionsFetchFailed { hashes } => {
                self.drive_fetch::<LocalProvisionBinding>(FetchInput::Failed { ids: hashes });
            }
            ShardScopedInput::FinalizedWavesFetchFailed { ids } => {
                self.drive_fetch::<FinalizedWaveBinding>(FetchInput::Failed { ids });
            }

            // ── Committed header (gossip → BLS verify → state machine) ──
            ShardScopedInput::CommittedBlockGossipReceived {
                committed_header,
                sender,
                public_key,
                sender_signature,
            } => self.handle_committed_block_gossip_received(
                committed_header,
                sender,
                public_key,
                sender_signature,
            ),
        }
    }

    /// Fan a shard-scoped protocol event out to every hosted vnode in
    /// this shard and dispatch each vnode's resulting actions.
    ///
    /// Every same-shard vnode independently applies the event at the
    /// shard's cached `now` and produces its own signed actions.
    pub(crate) fn dispatch_event(&mut self, event: ProtocolEvent) {
        let count = self.vnodes.len();
        if count == 0 {
            return;
        }
        let now = self.now;
        // Clone for every recipient except the last; move into the last
        // so we don't pay a final clone whose result is immediately
        // dropped.
        for vnode_idx in 0..count - 1 {
            let ev = event.clone();
            let actions = self.vnode_mut(vnode_idx).state.handle(now, ev);
            self.drain_actions(vnode_idx, actions);
        }
        let actions = self.vnode_mut(count - 1).state.handle(now, event);
        self.drain_actions(count - 1, actions);
    }

    /// Dispatch a `Vec<Action>` produced by a vnode's state machine.
    /// Bumps the step's action counter, processes each action with the
    /// emitting vnode's signing context, and flushes pending block
    /// commits at the tail.
    pub(crate) fn drain_actions(&mut self, vnode_idx: usize, actions: Vec<Action>) {
        self.actions_generated += actions.len();
        for action in actions {
            self.process_action(vnode_idx, action);
        }
        self.flush_block_commits();
    }
}
