//! The shard half of a vnode: the coordinators a node runs while seated on
//! a shard, plus the per-domain dispatch over them.
//!
//! [`ShardParticipation`] bundles [`ShardCoordinator`], [`ExecutionCoordinator`],
//! [`MempoolCoordinator`], [`ProvisionCoordinator`], [`OutboundProvisionTracker`],
//! and [`RemoteHeaderCoordinator`]. [`NodeStateMachine`](super::NodeStateMachine)
//! holds it behind an `Option`: present while seated, absent for a vnode that
//! only follows the beacon.
//!
//! The per-domain dispatch (the [`shard`], [`execution`], [`provisions`],
//! [`transactions`], [`sync`], [`timers`], [`proposal`] submodules) lives here as
//! methods on `ShardParticipation`. Each takes the per-epoch
//! [`TopologySchedule`] as a parameter — the beacon projection these handlers
//! verify against — rather than reaching back into the enclosing machine. The
//! few flows that also mutate the beacon coordinator stay on `NodeStateMachine`
//! as orchestrators (see [`super::orchestration`]).

mod execution;
mod proposal;
mod provisions;
mod shard;
mod sync;
mod timers;
mod transactions;

use std::sync::Arc;

use hyperscale_execution::{ExecCertStore, ExecutionCoordinator, FinalizationStore};
use hyperscale_mempool::{MempoolConfig, MempoolCoordinator, TxStore};
use hyperscale_provisions::{
    OutboundProvisionTracker, ProvisionConfig, ProvisionCoordinator, ProvisionStore,
};
use hyperscale_remote_headers::RemoteHeaderCoordinator;
use hyperscale_shard::{ShardConsensusConfig, ShardCoordinator};
use hyperscale_storage::RecoveredState;
use hyperscale_types::{
    BlockHeight, Derivation, ForkFence, LocalTimestamp, ShardId, ValidatorId, Verifier,
};

/// The coordinators a vnode runs while seated on a shard.
///
/// Fields are visible across the `state` module tree so the per-domain handlers
/// here, the orchestrators on [`NodeStateMachine`](super::NodeStateMachine), and
/// its accessors all read them directly.
pub(in crate::state) struct ShardParticipation {
    /// This vnode's home shard.
    pub(in crate::state) local_shard: ShardId,

    /// What this node can resolve an envelope against. Blocks that
    /// arrive already verified carry their derivation; the ones lifted
    /// out of storage carry none, so the handlers that take them derive
    /// through this before any coordinator reads a routed fact.
    pub(in crate::state) derivation: Arc<dyn Derivation>,

    /// Shard consensus state (includes implicit round advancement).
    pub(in crate::state) shard_coordinator: ShardCoordinator,

    /// Execution state.
    pub(in crate::state) execution_coordinator: ExecutionCoordinator,

    /// Mempool state.
    pub(in crate::state) mempool_coordinator: MempoolCoordinator,

    /// Provision coordination for cross-shard transactions.
    pub(in crate::state) provisions_coordinator: ProvisionCoordinator,

    /// Retains outbound provisions until the target shard's execution
    /// certificates ACK every transaction they contain.
    pub(in crate::state) outbound_provisions: OutboundProvisionTracker,

    /// Remote block header coordination (single source of truth).
    pub(in crate::state) remote_headers_coordinator: RemoteHeaderCoordinator,

    /// Current time, mirrored from the enclosing machine so shard handlers read
    /// a consistent stamp without threading it through every signature.
    pub(in crate::state) now: LocalTimestamp,

    /// Latches the one-shot terminal sweep: when the local chain terminates at a
    /// reshape boundary (the first coast commit), every in-flight transaction
    /// and pending tick is aborted exactly once — no later block can ever decide
    /// them.
    pub(in crate::state) terminal_chain_swept: bool,

    /// Latches the pending-pool handback, and counts the offers made
    /// before it latched. Whatever the local chain admitted and never
    /// included is offered back to the network as it coasts to its
    /// dissolution; the sweep above cannot reach those entries, because
    /// an aborted transaction is a decided one and these were never
    /// decided by anything.
    pub(in crate::state) pending_pool_handed_back: bool,
    pub(in crate::state) handback_attempts: u32,

    /// Committed height observed at the previous cleanup tick, and how many
    /// consecutive cleanup ticks it has gone unchanged. The cross-shard fallback
    /// fetches are otherwise only swept on block commit; once the shard has
    /// stalled for [`timers::STALL_RECOVERY_TICKS`] ticks they are flushed from
    /// the cleanup timer so a shard stuck on missing cross-shard data can still
    /// fetch it.
    pub(in crate::state) last_cleanup_height: Option<BlockHeight>,
    pub(in crate::state) cleanup_stall_ticks: u32,

    /// Dedup fence for verified fork proofs: one engage-and-regossip per
    /// forked shard, so a later proof for an already-fenced shard is
    /// ignored. Engaged and cleared on the same edges as the consuming
    /// coordinators' fences (see [`ForkFence`]), so a re-fork after a
    /// completed recovery can re-engage. Empty under honest operation.
    pub(in crate::state) fork_fence: ForkFence,
}

impl ShardParticipation {
    /// Build the shard half from the same per-shard-shared stores
    /// [`NodeStateMachine::new`](super::NodeStateMachine::new) threads in. Use
    /// `RecoveredState::default()` for a fresh start.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // per-shard-shared stores threaded explicitly
    pub(in crate::state) fn new(
        verifier: Arc<dyn Verifier>,
        derivation: Arc<dyn Derivation>,
        me: ValidatorId,
        local_shard: ShardId,
        shard_config: &ShardConsensusConfig,
        recovered: &RecoveredState,
        mempool_config: MempoolConfig,
        provision_config: ProvisionConfig,
        provision_store: Arc<ProvisionStore>,
        tx_store: Arc<TxStore>,
        exec_cert_store: Arc<ExecCertStore>,
        finalization_store: Arc<FinalizationStore>,
    ) -> Self {
        let mempool_coordinator =
            MempoolCoordinator::with_tx_store(local_shard, mempool_config, tx_store);
        // Execution's commit frontier and its account of what is still in
        // flight both seed from the same recovered tip the shard
        // coordinator restores, so the first post-restart commit
        // classifies its ticks exactly as a non-restarted peer's does.
        let shard_coordinator = ShardCoordinator::new(
            verifier,
            me,
            local_shard,
            shard_config.clone(),
            recovered.clone(),
        );
        // One mirror of the commit-proven remote anchors, one of the
        // cells this validator has proven under them, and one of what
        // counterparts have said, all owned by the shard coordinator:
        // the vote fence and the execution coordinator ask the same
        // questions of them, and two copies could answer differently.
        let execution_coordinator = ExecutionCoordinator::with_shared_stores(
            me,
            local_shard,
            recovered,
            exec_cert_store,
            finalization_store,
            Arc::clone(shard_coordinator.proven_anchors()),
            Arc::clone(shard_coordinator.proven_cells()),
            Arc::clone(shard_coordinator.mirror()),
        );
        Self {
            local_shard,
            derivation,
            shard_coordinator,
            execution_coordinator,
            mempool_coordinator,
            provisions_coordinator: ProvisionCoordinator::with_config_and_store(
                local_shard,
                provision_config,
                Arc::clone(&provision_store),
            ),
            outbound_provisions: OutboundProvisionTracker::new(provision_store),
            remote_headers_coordinator: RemoteHeaderCoordinator::new(local_shard),
            now: LocalTimestamp::ZERO,
            terminal_chain_swept: false,
            pending_pool_handed_back: false,
            handback_attempts: 0,
            last_cleanup_height: None,
            cleanup_stall_ticks: 0,
            fork_fence: ForkFence::new(),
        }
    }

    /// Push the current wall-clock into the shard and mempool coordinators
    /// and the mirrored `now`, before any handler runs.
    pub(in crate::state) const fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
        self.shard_coordinator.set_time(now);
        self.mempool_coordinator.set_time(now);
    }
}
