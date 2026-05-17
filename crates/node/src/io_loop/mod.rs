//! Unified I/O loop for action processing.
//!
//! `IoLoop` handles ALL actions from `NodeStateMachine`, dispatching them via
//! generic trait methods (Network, Dispatch, Storage) and concrete types for
//! timer ops and event delivery. Both production and simulation runners construct
//! an `IoLoop` with their concrete trait implementations.
//!
//! # Driving modes
//!
//! - **Production**: `IoLoop::run()` blocks on a crossbeam channel, processing
//!   events as they arrive from tokio bridge tasks.
//! - **Simulation**: The harness calls `IoLoop::step()` per event, then drains
//!   buffered outputs (timer ops, events, sync I/O).
//!
//! # Batching
//!
//! `IoLoop` batches execution-layer broadcasts and crypto verification for
//! efficiency. Batch deadlines are tracked as logical time (`Duration`) so both
//! production (wall clock) and simulation (logical clock) use the same paths.

mod actions;
mod fetch_io;
mod lifecycle;
mod metrics;
mod network_handlers;
mod status;
mod step;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam::channel::Sender;
use hyperscale_core::{Action, NodeInput, ProtocolEvent, StateMachine, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{Engine, RadixExecutor, TransactionValidation};
use hyperscale_network::Network;
use hyperscale_storage::{PendingChain, Storage};
use hyperscale_types::{LocalTimestamp, ShardGroupId, TopologySnapshot, TransactionStatus, TxHash};
pub use metrics::{MetricsSnapshot, record_metrics};
use quick_cache::sync::Cache as QuickCache;
pub use status::NodeStatusSnapshot;

use crate::NodeStateMachine;
use crate::batch_accumulator::BatchAccumulator;
use crate::config::NodeConfig;
use crate::shard::ShardIo;
use crate::shard::block_commit::{BlockCommitCoordinator, PreparedCommitMap};
use crate::shard::caches::SharedCaches;
use crate::shard::fetch::binding::{
    ExecCertBinding, FinalizedWaveBinding, LocalProvisionBinding, ProvisionBinding,
    TransactionBinding,
};
use crate::shard::fetch::{FetchHost, FetchInput};
use crate::shard::phase_times::TxPhaseTimesCache;
use crate::shard::sync::SyncHost;
use crate::vnode::{Vnode, VnodeInit};

/// Lock-free shared topology snapshot for handler closures and dispatch.
///
/// Updated by the `io_loop` when `Action::TopologyChanged` is processed.
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
pub(super) struct DispatchHandles<S: Storage, N, E: Engine> {
    pub(super) executor: E,
    pub(super) network: Arc<N>,
    pub(super) per_shard: HashMap<ShardGroupId, ShardDispatchHandles<S>>,
}

/// Per-shard subset of [`DispatchHandles`]. One entry per hosted shard.
pub(super) struct ShardDispatchHandles<S: Storage> {
    pub(super) pending_chain: Arc<PendingChain<S>>,
    pub(super) prepared_commits: Arc<Mutex<PreparedCommitMap<S>>>,
}

// ═══════════════════════════════════════════════════════════════════════
// TimerOp — buffered timer operations for the runner
// ═══════════════════════════════════════════════════════════════════════

/// A timer operation buffered by `IoLoop` for the runner to process.
#[derive(Debug, Clone)]
pub enum TimerOp {
    /// Set a timer to fire after `duration`.
    Set {
        /// Logical timer identifier (state-machine-side).
        id: TimerId,
        /// How long until the timer should fire.
        duration: Duration,
    },
    /// Cancel a previously set timer.
    Cancel {
        /// Logical timer identifier to cancel.
        id: TimerId,
    },
}

// ═══════════════════════════════════════════════════════════════════════
// StepOutput — returned to the caller after processing an event
// ═══════════════════════════════════════════════════════════════════════

/// Output from processing a single event via `IoLoop::step()`.
///
/// `IoLoop` now handles all sync/fetch I/O and block-commit dispatch
/// internally via the `Network` and `Dispatch` traits. The runner only
/// processes emitted transaction statuses and timer operations.
pub struct StepOutput {
    /// Transaction status notifications emitted during this step.
    pub emitted_statuses: Vec<(TxHash, TransactionStatus)>,
    /// Number of actions generated by the state machine during this step.
    pub actions_generated: usize,
    /// Timer operations (set/cancel) to be processed by the runner.
    pub timer_ops: Vec<TimerOp>,
}

// ═══════════════════════════════════════════════════════════════════════
// IoLoop
// ═══════════════════════════════════════════════════════════════════════

/// Unified I/O loop that processes all actions from the state machine.
///
/// Generic over:
/// - `S`: Storage (umbrella bound — see [`Storage`])
/// - `N`: Network (message sending)
/// - `D`: Dispatch (thread pool work scheduling)
/// - `E`: Engine (transaction execution — defaults to `RadixExecutor`)
pub struct IoLoop<S, N, D, E: Engine = RadixExecutor>
where
    S: Storage,
    D: Dispatch,
{
    /// Per-validator bundles. Each [`Vnode`] holds a `NodeStateMachine`,
    /// signing key, and per-step scratch buffers. Two or more vnodes
    /// in the same shard share a single [`ShardIo`] and consume the
    /// same inbound events; cross-shard vnodes live independently and
    /// each route to their own [`ShardIo`] via `vnode.shard`.
    ///
    /// State machines are driven exclusively from the pinned thread
    /// via `vnodes[i].state.handle()`. All `ProtocolEvent` ingestion
    /// and `Action` emission happen here; off-thread closures never
    /// touch them.
    vnodes: Vec<Vnode>,

    /// Per-shard I/O state, keyed by shard id. One entry per shard this
    /// host carries vnodes for. Per-shard helpers (`shard_io`,
    /// `shard_storage`, etc.) look up against this map.
    shards: HashMap<ShardGroupId, ShardIo<S>>,

    /// Transaction executor. Cloned (cheaply) into the block-commit
    /// closure on each drain — `Engine` requires `Clone`, so this is
    /// held by value rather than behind an `Arc`.
    executor: E,

    /// Network sender plus the registry of inbound gossip / request
    /// handlers installed at `init` time. `Arc` so handler closures
    /// and dispatch jobs can broadcast / reply without re-entering
    /// the pinned thread.
    network: Arc<N>,

    /// Thread-pool scheduler for off-thread work (crypto verify,
    /// tx validation, block-commit persistence, fetch-serve). Each
    /// `dispatch.spawn` site routes results back via `event_sender`.
    dispatch: D,

    /// Channel back to the pinned-thread event loop.
    ///
    /// Off-thread work spawned via `dispatch.spawn(pool, ...)` returns
    /// results here as `NodeInput` events, which the next pinned-thread
    /// `step()` iteration drains. Two routing rules:
    ///
    /// - **State-machine consumers** (BFT / execution / mempool — anything
    ///   driven by `state.handle()`) ride
    ///   `NodeInput::Protocol(ProtocolEvent::*)`. Examples: gossip BLS
    ///   verification emits `RemoteHeaderReceived`; block-commit drain
    ///   emits `BlockCommitted` / `BlockPersisted`.
    /// - **`IoLoop`-only consumers** (validation pipeline, sync
    ///   delivery, fetch retry — anything handled in `step()` directly
    ///   without entering the state machine) ride a dedicated top-level
    ///   `NodeInput` variant. Examples: `TransactionValidated`,
    ///   `SyncBlockValidated`, `*FetchFailed`.
    ///
    /// Failure handling is pattern-specific and intentional: drop on
    /// byzantine input (gossip), emit a typed failure variant when the
    /// `IoLoop` has cleanup to do (`TransactionValidationsFailed`,
    /// `SyncBlockValidationFailed`), abort on storage faults
    /// (block-commit). Don't paper over these in a generic helper —
    /// each `dispatch.spawn` site calls `event_sender.send` directly.
    event_sender: Sender<NodeInput>,

    /// Lock-free topology snapshot shared with network handler closures
    /// and delegated dispatch jobs. The pinned thread is the sole writer
    /// (via `Action::TopologyChanged`); all other readers `.load()` for
    /// an atomic snapshot. The state machine owns its own copy — this
    /// field exists for off-thread consumers that can't reach into it.
    topology_snapshot: SharedTopologySnapshot,

    /// See [`DispatchHandles`]. Cloned once per delegated-action dispatch.
    dispatch_handles: Arc<DispatchHandles<S, N, E>>,

    /// Stateless transaction validator (signature + format + EC checks).
    /// `Arc` so it can be cloned into the `tx_validation` pool closure
    /// on each batch flush.
    tx_validator: Arc<TransactionValidation>,

    /// Last time a "transaction finalization exceeded 10s" warning was emitted.
    /// Rate-limited to avoid flooding logs during cross-shard latency spikes.
    last_slow_tx_warn: LocalTimestamp,

    /// Per-tx phase-time stamps for the slow-tx finalization log. Populated
    /// from `EmitTransactionStatus` and `RecordTxEcCreated` actions; entries
    /// are dropped on terminal status.
    tx_phase_times: TxPhaseTimesCache,
}

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Create a new `IoLoop` hosting one or more `Vnode`s, possibly
    /// across multiple shards.
    ///
    /// `storages` carries one storage handle per hosted shard. The set
    /// of hosted shards is derived from `vnodes` (each vnode's
    /// `local_shard()`); `storages` must cover all of them.
    ///
    /// # Panics
    ///
    /// Panics if `vnodes` is empty, or if any hosted shard lacks a
    /// matching entry in `storages`.
    // `config: NodeConfig` is taken by value: every caller hands over a fresh
    // config and we destructure sub-configs via `.clone()`, so a `&NodeConfig`
    // would just force the body to clone each subfield.
    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
    pub fn new(
        vnodes: Vec<VnodeInit>,
        mut storages: HashMap<ShardGroupId, S>,
        executor: E,
        network: N,
        dispatch: D,
        event_sender: Sender<NodeInput>,
        topology_snapshot: SharedTopologySnapshot,
        config: NodeConfig,
        tx_validator: Arc<TransactionValidation>,
    ) -> Self {
        assert!(!vnodes.is_empty(), "IoLoop requires at least one Vnode");

        // Distinct shards this host carries, derived from the supplied
        // vnodes. Used to allocate one `ShardIo` per shard.
        let hosted_shards: HashSet<ShardGroupId> = vnodes
            .iter()
            .map(|v| v.state.topology().local_shard())
            .collect();

        let b = &config.batch;
        let network = Arc::new(network);

        // Build one `ShardIo` + matching dispatch handles per hosted
        // shard. The representative vnode for each shard supplies the
        // initial-persisted height and the inbound-serving caches —
        // same-shard vnodes admit identical transactions and provisions
        // by determinism, so any same-shard vnode's stores are
        // consistent (each shard's vnodes still hold their own copies
        // inside their state machines).
        let mut shards: HashMap<ShardGroupId, ShardIo<S>> = HashMap::new();
        let mut per_shard_dispatch: HashMap<ShardGroupId, ShardDispatchHandles<S>> = HashMap::new();
        for shard in &hosted_shards {
            let rep = vnodes
                .iter()
                .find(|v| v.state.topology().local_shard() == *shard)
                .expect("hosted shard derived from vnodes — at least one vnode exists for it");
            let initial_persisted_height = rep.state.bft().committed_height();
            let caches = SharedCaches::new(
                Arc::clone(rep.state.provisions().store()),
                Arc::clone(rep.state.mempool().tx_store()),
                Arc::clone(rep.state.execution().exec_cert_store()),
            );
            let storage = storages
                .remove(shard)
                .unwrap_or_else(|| panic!("IoLoop: missing storage for hosted shard {shard:?}"));
            let storage = Arc::new(storage);
            let pending_chain = Arc::new(PendingChain::new(Arc::clone(&storage)));
            let block_commit = BlockCommitCoordinator::new(initial_persisted_height);
            per_shard_dispatch.insert(
                *shard,
                ShardDispatchHandles {
                    pending_chain: Arc::clone(&pending_chain),
                    prepared_commits: block_commit.prepared_commits_handle(),
                },
            );
            shards.insert(
                *shard,
                ShardIo {
                    storage,
                    pending_chain,
                    block_commit,
                    caches,
                    fetches: FetchHost::new(&config),
                    syncs: SyncHost::new(&config),
                    pending_validation: HashSet::new(),
                    locally_submitted: HashSet::new(),
                    validation_batch: BatchAccumulator::new(
                        b.tx_validation_max,
                        b.tx_validation_window,
                    ),
                    committed_header_batch: BatchAccumulator::new(
                        b.committed_header_max,
                        b.committed_header_window,
                    ),
                    tx_gossip_batches: std::collections::BTreeMap::new(),
                    tx_gossip_max: b.tx_gossip_max,
                    tx_gossip_window: b.tx_gossip_window,
                },
            );
        }

        let dispatch_handles = Arc::new(DispatchHandles {
            executor: executor.clone(),
            network: Arc::clone(&network),
            per_shard: per_shard_dispatch,
        });
        let vnodes: Vec<Vnode> = vnodes
            .into_iter()
            .map(|init| Vnode {
                validator_id: init.state.topology().local_validator_id(),
                shard: init.state.topology().local_shard(),
                state: init.state,
                signing_key: Arc::new(init.signing_key),
                emitted_statuses: Vec::new(),
                actions_generated: 0,
                pending_timer_ops: Vec::new(),
            })
            .collect();
        Self {
            vnodes,
            shards,
            executor,
            network,
            dispatch,
            event_sender,
            topology_snapshot,
            dispatch_handles,
            tx_validator,
            last_slow_tx_warn: LocalTimestamp::ZERO,
            tx_phase_times: TxPhaseTimesCache::default(),
        }
    }

    // ─── Time ────────────────────────────────────────────────────────────

    /// Set the state machine's current time.
    ///
    /// Must be called before `step()` to keep the state machine's clock
    /// in sync with the driving environment.
    pub fn set_time(&mut self, now: LocalTimestamp) {
        for vnode in &mut self.vnodes {
            vnode.state.set_time(now);
        }
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Access the (sole) vnode's state machine.
    pub fn state(&self) -> &NodeStateMachine {
        &self.vnodes[0].state
    }

    /// Mutably access the (sole) vnode's state machine.
    pub fn state_mut(&mut self) -> &mut NodeStateMachine {
        &mut self.vnodes[0].state
    }

    /// Number of vnodes hosted by this `IoLoop`.
    #[must_use]
    pub const fn vnodes_len(&self) -> usize {
        self.vnodes.len()
    }

    /// Access the state machine of the vnode at `vnode_idx`.
    ///
    /// # Panics
    /// Panics if `vnode_idx >= vnodes_len()`.
    pub fn vnode_state(&self, vnode_idx: usize) -> &NodeStateMachine {
        &self.vnodes[vnode_idx].state
    }

    /// Mutably access the state machine of the vnode at `vnode_idx`.
    ///
    /// # Panics
    /// Panics if `vnode_idx >= vnodes_len()`.
    pub fn vnode_state_mut(&mut self, vnode_idx: usize) -> &mut NodeStateMachine {
        &mut self.vnodes[vnode_idx].state
    }

    /// Hosted shards (one entry per `ShardIo`). Used by call sites that
    /// fan out across every shard this host carries — batch flushes,
    /// fetch ticks, metrics aggregation.
    pub fn hosted_shards(&self) -> impl Iterator<Item = ShardGroupId> + '_ {
        self.shards.keys().copied()
    }

    /// Internal: shared `ShardIo` for `shard`. Call sites that touch
    /// several fields of one shard prefer this over the per-field
    /// helpers below.
    pub(super) fn shard_io(&self, shard: ShardGroupId) -> &ShardIo<S> {
        self.shards
            .get(&shard)
            .unwrap_or_else(|| panic!("shard {shard:?} not hosted by this IoLoop"))
    }

    /// Internal: mutable `ShardIo` for `shard`.
    pub(super) fn shard_io_mut(&mut self, shard: ShardGroupId) -> &mut ShardIo<S> {
        self.shards
            .get_mut(&shard)
            .unwrap_or_else(|| panic!("shard {shard:?} not hosted by this IoLoop"))
    }

    /// Shard storage as `&Arc<S>` for sites that need to `Arc::clone`
    /// it into off-thread handler closures (e.g. runners executing
    /// genesis on per-shard storage).
    pub fn shard_storage(&self, shard: ShardGroupId) -> &Arc<S> {
        &self.shard_io(shard).storage
    }

    /// Internal: shard pending-chain handle. Used by JMT-snapshot
    /// inserts and persistence prunes that need to mutate the pending
    /// chain through its `Arc`-shared interior mutability.
    pub(super) fn shard_pending_chain(&self, shard: ShardGroupId) -> &Arc<PendingChain<S>> {
        &self.shard_io(shard).pending_chain
    }

    /// Internal: immutable view of the shard's block-commit pipeline.
    pub(super) fn shard_block_commit(&self, shard: ShardGroupId) -> &BlockCommitCoordinator<S> {
        &self.shard_io(shard).block_commit
    }

    /// Internal: mutable view of the shard's block-commit pipeline.
    pub(super) fn shard_block_commit_mut(
        &mut self,
        shard: ShardGroupId,
    ) -> &mut BlockCommitCoordinator<S> {
        &mut self.shard_io_mut(shard).block_commit
    }

    /// Internal: shared inbound-serving caches for the shard.
    pub(super) fn shard_caches(&self, shard: ShardGroupId) -> &SharedCaches {
        &self.shard_io(shard).caches
    }

    /// Internal: per-payload fetch state machines for the shard.
    pub(super) fn shard_fetches(&self, shard: ShardGroupId) -> &FetchHost {
        &self.shard_io(shard).fetches
    }

    /// Internal: mutable view of the shard's fetch host. Required by
    /// `FetchBinding::fetch_mut`, which routes inputs to the correct
    /// per-payload state machine.
    pub(super) fn shard_fetches_mut(&mut self, shard: ShardGroupId) -> &mut FetchHost {
        &mut self.shard_io_mut(shard).fetches
    }

    /// Internal: sync state machines for the shard (block-sync,
    /// remote-header sync).
    pub(super) fn shard_syncs(&self, shard: ShardGroupId) -> &SyncHost {
        &self.shard_io(shard).syncs
    }

    /// Internal: mutable view of the shard's sync state.
    pub(super) fn shard_syncs_mut(&mut self, shard: ShardGroupId) -> &mut SyncHost {
        &mut self.shard_io_mut(shard).syncs
    }

    /// Access the network.
    pub fn network(&self) -> &N {
        &self.network
    }

    /// Look up the latest emitted status for a transaction across every
    /// hosted shard.
    ///
    /// Returns the most recent status notification for the given transaction
    /// hash, if any status has been emitted on any hosted shard. Unlike the
    /// per-step `StepOutput::emitted_statuses`, this cache persists across
    /// steps and survives mempool eviction.
    pub fn tx_status(&self, hash: &TxHash) -> Option<TransactionStatus> {
        self.shards
            .values()
            .find_map(|sio| sio.caches.tx_status.get(hash))
    }

    /// Per-shard transaction status caches.
    ///
    /// Each cache is an `Arc<QuickCache>` so external consumers (e.g. RPC
    /// handlers) can share lock-free reads across threads. RPC layers
    /// typically hold the full set so a single-hash lookup can fan out
    /// across every hosted shard without re-entering the pinned thread.
    pub fn tx_status_caches(
        &self,
    ) -> HashMap<ShardGroupId, Arc<QuickCache<TxHash, TransactionStatus>>> {
        self.shards
            .iter()
            .map(|(shard, sio)| (*shard, Arc::clone(&sio.caches.tx_status)))
            .collect()
    }

    // ─── Event Processing ───────────────────────────────────────────────

    /// Process a single event through the state machine and handle all resulting actions.
    ///
    /// Returns a [`StepOutput`] containing emitted transaction statuses and timer
    /// operations. Sync/fetch I/O is handled internally via the Network trait.
    ///
    /// # Caller protocol
    ///
    /// After each call to `step()`, the runner should:
    /// 1. Flush batches — either [`Self::flush_all_batches`] (simulation) or
    ///    [`Self::flush_expired_batches`] (production, with wall-clock time)
    /// 2. Process `timer_ops` from the returned [`StepOutput`]
    /// 3. Process `emitted_statuses` from the returned [`StepOutput`]
    /// 4. Drain any events produced through the event channel (simulation only —
    ///    production receives these via its crossbeam channel receivers)
    #[allow(clippy::too_many_lines)] // single dispatch over NodeInput; one arm per event variant
    pub fn step(&mut self, event: NodeInput) -> StepOutput {
        for vnode in &mut self.vnodes {
            vnode.emitted_statuses.clear();
            vnode.actions_generated = 0;
            vnode.pending_timer_ops.clear();
        }

        // Inbound-callback events (`*FetchFailed`, sync responses,
        // validation results, gossip arrivals) don't yet carry the
        // local shard that originated the fetch / subscription. For
        // single-shard hosting that's a non-issue — there's exactly
        // one — and we route every such event to the first-hosted
        // shard's `ShardIo`. Cross-shard hosting that actually
        // exercises these paths must thread `local_shard` through the
        // corresponding `NodeInput` variants and their dispatch sites;
        // the smoke test for V=2 cross-shard construction below does
        // not drive consensus, so this fallback is safe there.
        let primary_shard = self.vnodes[0].shard;

        match event {
            // ── Transaction validation pipeline ────────────────────────
            NodeInput::TransactionGossipReceived { tx } => {
                self.handle_gossip_received_tx_for_validation(primary_shard, tx);
            }
            NodeInput::TransactionValidated { tx } => {
                self.handle_transaction_validated(primary_shard, tx);
            }
            NodeInput::TransactionValidationsFailed { hashes } => {
                self.handle_transaction_validations_failed(primary_shard, &hashes);
            }
            NodeInput::Protocol(pe) => match *pe {
                ProtocolEvent::BlockPersisted { height } => {
                    self.handle_block_persisted(primary_shard, height);
                }
                other => self.handle_protocol_passthrough(primary_shard, other),
            },
            NodeInput::SubmitTransaction { tx } => {
                self.handle_submit_transaction(primary_shard, tx);
            }

            // ── Sync protocol ──────────────────────────────────────────
            NodeInput::BlockSyncResponseReceived { height, block } => {
                self.handle_block_sync_response_received(primary_shard, height, block);
            }
            NodeInput::BlockSyncFetchFailed { height, kind } => {
                self.handle_block_sync_fetch_failed(primary_shard, height, kind);
            }
            NodeInput::SyncBlockValidated { height, certified } => {
                self.handle_sync_block_validated(primary_shard, height, *certified);
            }
            NodeInput::SyncBlockValidationFailed { height, reason } => {
                self.handle_sync_block_validation_failed(primary_shard, height, reason);
            }
            NodeInput::RemoteHeadersResponseReceived {
                source_shard,
                from_height,
                count,
                headers,
            } => {
                self.handle_remote_headers_response_received(
                    primary_shard,
                    source_shard,
                    from_height,
                    count,
                    headers,
                );
            }
            NodeInput::RemoteHeadersFetchFailed {
                source_shard,
                from_height,
                count,
                kind,
            } => {
                self.handle_remote_headers_fetch_failed(
                    primary_shard,
                    source_shard,
                    from_height,
                    count,
                    kind,
                );
            }

            // ── Fetch protocol ─────────────────────────────────────────
            NodeInput::TransactionsFetchFailed { hashes } => {
                self.drive_fetch::<TransactionBinding>(
                    primary_shard,
                    FetchInput::Failed { ids: hashes },
                );
                self.update_fetch_tick_timer(primary_shard);
            }

            NodeInput::FetchTick => self.handle_fetch_tick(),

            NodeInput::ProvisionsFetchFailed {
                source_shard,
                block_height,
            } => {
                self.drive_fetch::<ProvisionBinding>(
                    primary_shard,
                    FetchInput::Failed {
                        ids: vec![(source_shard, primary_shard, block_height)],
                    },
                );
                self.update_fetch_tick_timer(primary_shard);
            }

            NodeInput::ExecCertFetchFailed { hashes } => {
                self.drive_fetch::<ExecCertBinding>(
                    primary_shard,
                    FetchInput::Failed { ids: hashes },
                );
                self.update_fetch_tick_timer(primary_shard);
            }

            // ── Committed header (gossip → BLS verify → state machine) ──
            NodeInput::CommittedBlockGossipReceived {
                committed_header,
                sender,
                public_key,
                sender_signature,
            } => self.handle_committed_block_gossip_received(
                primary_shard,
                *committed_header,
                sender,
                public_key,
                sender_signature,
            ),

            NodeInput::LocalProvisionsFetchFailed { hashes } => {
                self.drive_fetch::<LocalProvisionBinding>(
                    primary_shard,
                    FetchInput::Failed { ids: hashes },
                );
                self.update_fetch_tick_timer(primary_shard);
            }

            NodeInput::FinalizedWavesFetchFailed { ids } => {
                self.drive_fetch::<FinalizedWaveBinding>(primary_shard, FetchInput::Failed { ids });
                self.update_fetch_tick_timer(primary_shard);
            }
        }

        self.drain_pending_output()
    }

    /// Drain accumulated outputs (statuses, timer ops) across every
    /// vnode without processing an event.
    ///
    /// Used after `handle_actions()` to collect outputs produced by
    /// those actions.
    pub fn drain_pending_output(&mut self) -> StepOutput {
        let mut emitted_statuses = Vec::new();
        let mut timer_ops = Vec::new();
        let mut actions_generated = 0usize;
        for vnode in &mut self.vnodes {
            emitted_statuses.append(&mut vnode.emitted_statuses);
            timer_ops.append(&mut vnode.pending_timer_ops);
            actions_generated += vnode.actions_generated;
        }
        StepOutput {
            emitted_statuses,
            actions_generated,
            timer_ops,
        }
    }

    /// Feed a protocol event to the named vnode's state machine and
    /// process all resulting actions.
    ///
    /// This is the common pattern used throughout `IoLoop`: route an
    /// event through a state machine, then dispatch each resulting
    /// action with the originating vnode's signing context.
    fn feed_event(&mut self, vnode_idx: usize, event: ProtocolEvent) {
        let actions = self.vnodes[vnode_idx].state.handle(event);
        self.process_actions(vnode_idx, actions);
    }

    /// Fan a protocol event out to every hosted vnode's state machine.
    ///
    /// Use this for shard-derived events (block persisted, sync block
    /// validated, remote header received, etc.) — each same-shard
    /// vnode independently applies the event and produces its own
    /// signed actions. Per-vnode events (where only the emitting vnode
    /// should react) should call [`Self::feed_event`] directly with
    /// the originating index.
    fn feed_event_to_all_vnodes(&mut self, event: ProtocolEvent) {
        // Clone for every vnode except the last; move into the last so
        // we don't pay a final clone whose result is immediately
        // dropped.
        let last = self.vnodes.len().saturating_sub(1);
        for vnode_idx in 0..last {
            self.feed_event(vnode_idx, event.clone());
        }
        if !self.vnodes.is_empty() {
            self.feed_event(last, event);
        }
    }

    /// Dispatch a `Vec<Action>` produced by a direct state-machine
    /// method call. Mirrors [`Self::feed_event`]'s post-`handle` block
    /// — bumps `actions_generated`, dispatches each action, and
    /// flushes pending block commits. The flush is the load-bearing
    /// part: it's easy to forget when copy-pasting the loop inline.
    fn process_actions(&mut self, vnode_idx: usize, actions: Vec<Action>) {
        let shard = self.vnodes[vnode_idx].shard;
        self.vnodes[vnode_idx].actions_generated += actions.len();
        for action in actions {
            self.process_action(vnode_idx, action);
        }
        self.flush_block_commits(shard);
    }

    /// Flush any batch accumulators whose deadlines have expired across
    /// every hosted shard.
    ///
    /// Call this with the current time before processing events. In production,
    /// the loop calls this with wall-clock time. In simulation, the harness
    /// calls it with logical time.
    pub fn flush_expired_batches(&mut self, now: LocalTimestamp) {
        let hosted: Vec<ShardGroupId> = self.hosted_shards().collect();
        for shard in hosted {
            let sio = self.shard_io(shard);
            if sio.validation_batch.is_expired(now) {
                self.flush_validation_batch(shard);
            }
            if self.shard_io(shard).committed_header_batch.is_expired(now) {
                self.flush_committed_header_verifications(shard);
            }
            let expired_dst_shards: Vec<ShardGroupId> = self
                .shard_io(shard)
                .tx_gossip_batches
                .iter()
                .filter_map(|(dst, batch)| batch.is_expired(now).then_some(*dst))
                .collect();
            for dst in expired_dst_shards {
                self.flush_tx_gossip_batch(shard, dst);
            }
        }
    }

    /// Get the nearest batch deadline across every hosted shard, if any.
    ///
    /// Used by the production `run()` loop for `recv_timeout()` and by the
    /// simulation harness to know when to schedule a flush.
    pub fn nearest_batch_deadline(&self) -> Option<LocalTimestamp> {
        self.shards
            .values()
            .flat_map(|sio| {
                let tx_gossip_min = sio
                    .tx_gossip_batches
                    .values()
                    .filter_map(BatchAccumulator::deadline)
                    .min();
                [
                    sio.validation_batch.deadline(),
                    sio.committed_header_batch.deadline(),
                    tx_gossip_min,
                ]
            })
            .flatten()
            .min()
    }

    /// Flush ALL pending batches across every hosted shard immediately,
    /// regardless of deadlines.
    ///
    /// Called during shutdown or when immediate delivery is needed.
    pub fn flush_all_batches(&mut self) {
        let hosted: Vec<ShardGroupId> = self.hosted_shards().collect();
        for shard in &hosted {
            self.flush_block_commits(*shard);
            self.flush_validation_batch(*shard);
            self.flush_committed_header_verifications(*shard);
            let dst_shards: Vec<ShardGroupId> = self
                .shard_io(*shard)
                .tx_gossip_batches
                .keys()
                .copied()
                .collect();
            for dst in dst_shards {
                self.flush_tx_gossip_batch(*shard, dst);
            }
        }
    }
}
