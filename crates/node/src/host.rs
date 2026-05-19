//! Top-level node composition: [`NodeHost`].
//!
//! `NodeHost` bundles `Arc<ProcessIo>` (process-scoped resources) plus
//! one [`ShardLoop`] per hosted shard. It owns the event-routing seam:
//! [`Self::step`] dispatches `ShardEvent::Shard` to the targeted
//! `ShardLoop::step` and `ShardEvent::Process` to cross-shard handlers
//! (transaction submission fan-out, fetch tick) that need access to
//! every hosted shard.
//!
//! Production and simulation runners both build a `NodeHost` via
//! [`Self::new`] and drive it through [`Self::step`] / [`Self::set_time`].

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{Engine, RadixExecutor, TransactionValidation};
use hyperscale_network::Network;
use hyperscale_storage::{PendingChain, Storage};
use hyperscale_types::{LocalTimestamp, ShardGroupId, TransactionStatus, TxHash};
use quick_cache::sync::Cache as QuickCache;

use crate::NodeStateMachine;
use crate::batch_accumulator::BatchAccumulator;
use crate::config::NodeConfig;
use crate::process_io::ProcessIo;
use crate::shard_io::ShardIo;
use crate::shard_io::block_commit::BlockCommitCoordinator;
use crate::shard_io::caches::SharedCaches;
use crate::shard_io::fetch::FetchHost;
use crate::shard_io::phase_times::TxPhaseTimesCache;
use crate::shard_io::sync::SyncHost;
use crate::shard_loop::{
    DispatchHandles, ProcessScopedInput, ShardDispatchHandles, ShardEvent, ShardLoop,
    SharedTopologySnapshot, StepOutput,
};
use crate::vnode::{Vnode, VnodeInit};

/// Top-level node composition: process-scoped resources plus one
/// [`ShardLoop`] per hosted shard.
///
/// Generic over:
/// - `S`: Storage (umbrella bound — see [`Storage`])
/// - `N`: Network (message sending)
/// - `D`: Dispatch (thread pool work scheduling)
/// - `E`: Engine (transaction execution — defaults to `RadixExecutor`)
pub struct NodeHost<S, N, D, E: Engine = RadixExecutor>
where
    S: Storage,
    D: Dispatch,
{
    /// One [`ShardLoop`] per hosted shard. State machines are driven
    /// exclusively through these — all `ProtocolEvent` ingestion and
    /// `Action` emission happen via per-shard `step()` dispatch.
    pub(crate) shards: HashMap<ShardGroupId, ShardLoop<S, N, D, E>>,

    /// Transaction executor. Cloned (cheaply) into the block-commit
    /// closure on each drain — `Engine` requires `Clone`, so this is
    /// held by value rather than behind an `Arc`.
    pub(crate) executor: E,

    /// Process-scoped shared resources: network adapter, dispatch pool,
    /// tx validator, topology snapshot, dispatch handles, event sender.
    /// Cloned `Arc::clone(&self.process)` is handed to every hosted
    /// `ShardLoop` so off-thread closures can capture it cheaply.
    pub(crate) process: Arc<ProcessIo<S, N, D, E>>,

    /// Process-wide wall-clock cache. Pushed into every hosted shard's
    /// own `now` via [`Self::set_time`] so off-thread handlers can read
    /// a consistent stamp without coordinating with this top-level cache.
    now: LocalTimestamp,
}

impl<S, N, D, E> NodeHost<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Create a new `NodeHost` hosting one or more `Vnode`s, possibly
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
    #[allow(
        clippy::too_many_arguments,
        clippy::needless_pass_by_value,
        clippy::too_many_lines
    )] // two-pass construction: build shard io, then process, then assemble
    pub fn new(
        vnodes: Vec<VnodeInit>,
        mut storages: HashMap<ShardGroupId, S>,
        executor: E,
        network: N,
        dispatch: D,
        event_sender: Sender<ShardEvent>,
        topology_snapshot: SharedTopologySnapshot,
        config: NodeConfig,
        tx_validator: Arc<TransactionValidation>,
    ) -> Self {
        assert!(!vnodes.is_empty(), "NodeHost requires at least one Vnode");

        // Distinct shards this host carries, derived from the supplied
        // vnodes. Used to allocate one `ShardIo` per shard.
        let hosted_shards: HashSet<ShardGroupId> = vnodes
            .iter()
            .map(|v| v.state.topology().local_shard())
            .collect();

        let b = &config.batch;
        let network = Arc::new(network);

        // First pass: build ShardIo + Vec<Vnode> for each shard, plus the
        // per-shard dispatch handles map. ShardLoop construction is deferred
        // to a second pass because each ShardLoop needs an Arc<ProcessIo>
        // that can only be built after dispatch_handles is finalized.
        let mut shard_builds: HashMap<ShardGroupId, (ShardIo<S>, Vec<Vnode>)> = HashMap::new();
        let mut per_shard_dispatch: HashMap<ShardGroupId, ShardDispatchHandles<S>> = HashMap::new();

        let mut by_shard: HashMap<ShardGroupId, Vec<VnodeInit>> = HashMap::new();
        for init in vnodes {
            let shard = init.state.topology().local_shard();
            by_shard.entry(shard).or_default().push(init);
        }

        for shard in &hosted_shards {
            let inits = by_shard
                .remove(shard)
                .expect("hosted shard derived from vnodes — at least one vnode exists for it");
            let rep = inits.first().expect("group non-empty by construction");
            let initial_persisted_height = rep.state.bft().committed_height();
            let caches = SharedCaches::new(
                Arc::clone(rep.state.provisions().store()),
                Arc::clone(rep.state.mempool().tx_store()),
                Arc::clone(rep.state.execution().exec_cert_store()),
                Arc::clone(rep.state.execution().finalized_wave_store()),
            );
            let storage = storages
                .remove(shard)
                .unwrap_or_else(|| panic!("NodeHost: missing storage for hosted shard {shard:?}"));
            let storage = Arc::new(storage);
            let pending_chain = Arc::new(PendingChain::new(Arc::clone(&storage)));
            let block_commit = BlockCommitCoordinator::new(*shard, initial_persisted_height);
            per_shard_dispatch.insert(
                *shard,
                ShardDispatchHandles {
                    pending_chain: Arc::clone(&pending_chain),
                    prepared_commits: block_commit.prepared_commits_handle(),
                },
            );
            let vnodes: Vec<Vnode> = inits
                .into_iter()
                .map(|init| Vnode {
                    validator_id: init.state.topology().local_validator_id(),
                    state: init.state,
                    signing_key: init.signing_key,
                })
                .collect();
            let io = ShardIo {
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
                tx_phase_times: TxPhaseTimesCache::default(),
                last_slow_tx_warn: LocalTimestamp::ZERO,
            };
            shard_builds.insert(*shard, (io, vnodes));
        }

        let dispatch_handles = Arc::new(DispatchHandles {
            executor: executor.clone(),
            network: Arc::clone(&network),
            per_shard: per_shard_dispatch,
        });
        let process = Arc::new(ProcessIo::new(
            network,
            dispatch,
            event_sender,
            topology_snapshot,
            dispatch_handles,
            tx_validator,
        ));

        // Second pass: assemble ShardLoops with cloned Arc<ProcessIo>.
        let tx_gossip_max = b.tx_gossip_max;
        let tx_gossip_window = b.tx_gossip_window;
        let shards: HashMap<ShardGroupId, ShardLoop<S, N, D, E>> = shard_builds
            .into_iter()
            .map(|(shard, (io, vnodes))| {
                let shard_loop = ShardLoop {
                    shard,
                    process: Arc::clone(&process),
                    io,
                    vnodes,
                    now: LocalTimestamp::ZERO,
                    pending_timer_ops: Vec::new(),
                    emitted_statuses: Vec::new(),
                    actions_generated: 0,
                    outbound_gossip_batches: std::collections::BTreeMap::new(),
                    tx_gossip_max,
                    tx_gossip_window,
                };
                (shard, shard_loop)
            })
            .collect();

        Self {
            shards,
            executor,
            process,
            now: LocalTimestamp::ZERO,
        }
    }

    // ─── Time ────────────────────────────────────────────────────────────

    /// Set the cached process-wide wall-clock time, propagated into every
    /// hosted shard so `state.handle(now, _)` calls observe the latest
    /// tick.
    pub fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
        for sl in self.shards.values_mut() {
            sl.now = now;
        }
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Number of vnodes hosted in `shard`, or `0` if `shard` isn't hosted.
    #[must_use]
    pub fn vnodes_len(&self, shard: ShardGroupId) -> usize {
        self.shards.get(&shard).map_or(0, |g| g.vnodes.len())
    }

    /// Access the state machine of the vnode at index `vnode_idx` within
    /// `shard`'s group.
    ///
    /// # Panics
    /// Panics if `shard` isn't hosted or `vnode_idx` is out of range.
    pub fn vnode_state(&self, shard: ShardGroupId, vnode_idx: usize) -> &NodeStateMachine {
        &self.shard_loop(shard).vnodes[vnode_idx].state
    }

    /// Mutably access the state machine of the vnode at index `vnode_idx`
    /// within `shard`'s group.
    ///
    /// # Panics
    /// Panics if `shard` isn't hosted or `vnode_idx` is out of range.
    pub fn vnode_state_mut(
        &mut self,
        shard: ShardGroupId,
        vnode_idx: usize,
    ) -> &mut NodeStateMachine {
        &mut self.shard_loop_mut(shard).vnodes[vnode_idx].state
    }

    /// Hosted shards (one entry per `ShardLoop`). Used by call sites
    /// that fan out across every shard this host carries — batch flushes,
    /// fetch ticks, metrics aggregation.
    pub fn hosted_shards(&self) -> impl Iterator<Item = ShardGroupId> + '_ {
        self.shards.keys().copied()
    }

    /// Internal: per-shard loop (process handle + io + vnodes + scratch).
    pub(crate) fn shard_loop(&self, shard: ShardGroupId) -> &ShardLoop<S, N, D, E> {
        self.shards
            .get(&shard)
            .unwrap_or_else(|| panic!("shard {shard:?} not hosted by this NodeHost"))
    }

    /// Internal: mutable per-shard loop.
    pub(crate) fn shard_loop_mut(&mut self, shard: ShardGroupId) -> &mut ShardLoop<S, N, D, E> {
        self.shards
            .get_mut(&shard)
            .unwrap_or_else(|| panic!("shard {shard:?} not hosted by this NodeHost"))
    }

    /// Internal: immutable per-shard vnode by index.
    pub(crate) fn vnode(&self, shard: ShardGroupId, vnode_idx: usize) -> &Vnode {
        &self.shard_loop(shard).vnodes[vnode_idx]
    }

    /// Shared `ShardIo` for `shard`. The single per-shard accessor;
    /// fields like `storage`, `caches`, `fetches`, `syncs`, `block_commit`,
    /// `pending_chain` are read directly off the returned reference.
    pub fn shard_io(&self, shard: ShardGroupId) -> &ShardIo<S> {
        &self.shard_loop(shard).io
    }

    /// Mutable `ShardIo` for `shard`. Use over multiple `_mut` calls
    /// when the borrow needs to span field-level reads and mutations
    /// (e.g. block-commit flush reading `&storage` while mutating
    /// `&mut block_commit`).
    pub(crate) fn shard_io_mut(&mut self, shard: ShardGroupId) -> &mut ShardIo<S> {
        &mut self.shard_loop_mut(shard).io
    }

    /// Access the network.
    pub fn network(&self) -> &N {
        &self.process.network
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
            .find_map(|group| group.io.caches.tx_status.get(hash))
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
            .map(|(shard, group)| (*shard, Arc::clone(&group.io.caches.tx_status)))
            .collect()
    }

    // ─── Event Processing ───────────────────────────────────────────────

    /// Process a single event through the state machine and handle all
    /// resulting actions.
    ///
    /// Returns a [`StepOutput`] containing emitted transaction statuses
    /// and timer operations. Sync/fetch I/O is handled internally via
    /// the `Network` trait.
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
    #[allow(clippy::too_many_lines)] // single dispatch over ShardEvent; one arm per variant
    pub fn step(&mut self, event: ShardEvent) -> StepOutput {
        for sl in self.shards.values_mut() {
            sl.pending_timer_ops.clear();
            sl.emitted_statuses.clear();
            sl.actions_generated = 0;
        }

        match event {
            ShardEvent::Shard(shard, input) => {
                // Silently drop events for shards we don't host — matches the
                // original `dispatch_event`'s `count == 0 { return }` guard.
                if let Some(sl) = self.shards.get_mut(&shard) {
                    sl.step(input);
                }
            }
            ShardEvent::Process(input) => self.step_process_input(input),
        }

        // Refresh the `FetchTick` timer once, after the event has fully
        // settled. Cheaper than the previous "call inline from every fetch
        // state change" pattern, and produces the same final timer state
        // because the runner applies timer ops sequentially — only the
        // last Set/Cancel for a (TimerId, shard) pair lands.
        self.update_fetch_tick_timer();

        self.drain_pending_output()
    }

    /// Dispatch a process-scoped input. Companion to [`Self::step`];
    /// one arm per [`ProcessScopedInput`] variant.
    fn step_process_input(&mut self, input: ProcessScopedInput) {
        match input {
            ProcessScopedInput::SubmitTransaction { tx } => {
                self.handle_submit_transaction(&tx);
            }
            ProcessScopedInput::FetchTick => self.handle_fetch_tick(),
        }
    }

    /// Drain accumulated step outputs (statuses, timer ops, action
    /// count) from every hosted shard's scratch.
    ///
    /// Used by [`Self::step`] at end of step and by lifecycle code that
    /// produces actions outside a normal step (genesis init, sync-output
    /// continuations).
    pub fn drain_pending_output(&mut self) -> StepOutput {
        let mut out = StepOutput {
            emitted_statuses: Vec::new(),
            actions_generated: 0,
            timer_ops: Vec::new(),
        };
        for sl in self.shards.values_mut() {
            out.emitted_statuses.append(&mut sl.emitted_statuses);
            out.actions_generated += std::mem::replace(&mut sl.actions_generated, 0);
            out.timer_ops.append(&mut sl.pending_timer_ops);
        }
        out
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
            let sl = self.shard_loop_mut(shard);
            if sl.io.validation_batch.is_expired(now) {
                sl.flush_validation_batch();
            }
            let sl = self.shard_loop_mut(shard);
            if sl.io.committed_header_batch.is_expired(now) {
                sl.flush_committed_header_verifications();
            }
            let sl = self.shard_loop_mut(shard);
            let expired_dsts: Vec<ShardGroupId> = sl
                .outbound_gossip_batches
                .iter()
                .filter_map(|(dst, batch)| batch.is_expired(now).then_some(*dst))
                .collect();
            for dst in expired_dsts {
                self.shard_loop_mut(shard).flush_tx_gossip_batch(dst);
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
            .flat_map(|sl| {
                [
                    sl.io.validation_batch.deadline(),
                    sl.io.committed_header_batch.deadline(),
                ]
                .into_iter()
                .chain(
                    sl.outbound_gossip_batches
                        .values()
                        .map(BatchAccumulator::deadline),
                )
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
            let sl = self.shard_loop_mut(*shard);
            sl.flush_block_commits();
            sl.flush_validation_batch();
            sl.flush_committed_header_verifications();
            let dsts: Vec<ShardGroupId> = sl.outbound_gossip_batches.keys().copied().collect();
            for dst in dsts {
                self.shard_loop_mut(*shard).flush_tx_gossip_batch(dst);
            }
        }
    }
}
