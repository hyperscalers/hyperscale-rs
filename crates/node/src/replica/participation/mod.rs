//! The shard half of a replica: the coordinators it runs on its shard,
//! plus the per-domain handlers over them.
//!
//! [`ShardParticipation`] bundles [`ShardCoordinator`], [`ExecutionCoordinator`],
//! [`MempoolCoordinator`], [`ProvisionCoordinator`], [`OutboundProvisionTracker`],
//! and [`RemoteHeaderCoordinator`]. [`NodeStateMachine`](super::NodeStateMachine)
//! holds one for its shard.
//!
//! The per-domain handlers (the [`shard`], [`execution`], [`provisions`],
//! [`transactions`], [`sync_completion`], [`timers`], [`proposal`] submodules) live here as
//! methods on `ShardParticipation`. Each takes the per-epoch
//! [`TopologySchedule`] as a parameter — the beacon projection these handlers
//! verify against — rather than reaching back into the enclosing machine. The
//! few flows that also report to the beacon stay on `NodeStateMachine` as
//! orchestrators (see [`super::orchestration`]).

mod execution;
mod proposal;
mod provisions;
mod shard;
mod sync_completion;
mod timers;
mod transactions;

use std::sync::Arc;

use hyperscale_execution::{
    CrossingIndexSlot, ExecCertStore, ExecutionCoordinator, FinalizationStore,
};
use hyperscale_mempool::{MempoolCoordinator, TxStore};
use hyperscale_provisions::{OutboundProvisionTracker, ProvisionCoordinator, ProvisionStore};
use hyperscale_remote_headers::RemoteHeaderCoordinator;
use hyperscale_shard::ShardCoordinator;
use hyperscale_storage::RecoveredState;
use hyperscale_types::{
    BlockHeight, Derivation, ForkFence, LocalTimestamp, ShardId, WeightedTimestamp,
};
use timers::{CommitStall, PoolHandback};

use crate::replica::ReplicaConfig;

/// The coordinators a replica runs on its shard.
///
/// Fields are visible across the `state` module tree so the per-domain handlers
/// here, the orchestrators on [`NodeStateMachine`](super::NodeStateMachine), and
/// its accessors all read them directly.
pub(in crate::replica) struct ShardParticipation {
    /// This replica's shard.
    pub(in crate::replica) local_shard: ShardId,

    /// What this node can resolve an envelope against. Blocks that
    /// arrive already verified carry their derivation; the ones lifted
    /// out of storage carry none, so the handlers that take them derive
    /// through this before any coordinator reads a routed fact.
    pub(in crate::replica) derivation: Arc<dyn Derivation>,

    /// Shard consensus state (includes implicit round advancement).
    pub(in crate::replica) shard_coordinator: ShardCoordinator,

    /// Execution state.
    pub(in crate::replica) execution_coordinator: ExecutionCoordinator,

    /// Mempool state.
    pub(in crate::replica) mempool_coordinator: MempoolCoordinator,

    /// Provision coordination for cross-shard transactions.
    pub(in crate::replica) provisions_coordinator: ProvisionCoordinator,

    /// Retains outbound provisions until the target shard's execution
    /// certificates ACK every transaction they contain.
    pub(in crate::replica) outbound_provisions: OutboundProvisionTracker,

    /// Remote block header coordination (single source of truth).
    pub(in crate::replica) remote_headers_coordinator: RemoteHeaderCoordinator,

    /// Current time, mirrored from the enclosing machine so shard handlers read
    /// a consistent stamp without threading it through every signature.
    pub(in crate::replica) now: LocalTimestamp,

    /// The pending-pool handback: whatever the local chain admitted and
    /// never included is offered back to the network as it coasts to its
    /// dissolution. The terminal abort of in-flight transactions cannot
    /// reach those entries, because an aborted transaction is a decided
    /// one and these were never decided by anything.
    handback: PoolHandback,

    /// How long the committed height has stood still across cleanup
    /// ticks. The cross-shard fallback fetches are otherwise only swept on
    /// block commit; once the shard stalls they are flushed from the
    /// cleanup timer so a shard stuck on missing cross-shard data can
    /// still fetch it.
    stall: CommitStall,

    /// The node's one fork fence (see [`ForkFence`]): engaged here on a
    /// verified proof, cleared once per commit as recoveries complete,
    /// and read by the mempool, provisions and remote-header coordinators
    /// through the handles they hold. It also dedups proofs: a later
    /// proof for an already-fenced shard is ignored, and a re-fork after
    /// a completed recovery can re-engage. Empty under honest operation.
    pub(in crate::replica) fork_fence: ForkFence,
}

impl ShardParticipation {
    /// Build the shard half from `recovered`, over a store written
    /// through `persisted_base`. Use `RecoveredState::default()` for a
    /// fresh start.
    ///
    /// The bodies the replica's own committed blocks carried go back in
    /// the provision store everything reads them from: a stored block
    /// keeps only their hashes, so without them a restarted host holds
    /// blocks it cannot serve and legs it cannot replay.
    #[must_use]
    pub(in crate::replica) fn new(
        config: &ReplicaConfig,
        local_shard: ShardId,
        recovered: &RecoveredState,
        genesis: WeightedTimestamp,
        persisted_base: BlockHeight,
    ) -> Self {
        let provision_store = Arc::new(ProvisionStore::new());
        for provisions in &recovered.retained_provisions {
            provision_store.insert(provisions.clone());
        }
        // Execution's commit frontier and its account of what is still in
        // flight both seed from the same recovered tip the shard
        // coordinator restores, so the first post-restart commit
        // classifies its ticks exactly as a non-restarted peer's does.
        let shard_coordinator = ShardCoordinator::new(
            Arc::clone(&config.verifier),
            local_shard,
            config.shard_config.clone(),
            recovered.clone(),
            genesis,
        );
        // One committed clock, seeded at the recovered tip and advanced by
        // the shard's commit, and one fork fence, which only this machine
        // engages and clears: the coordinators below read both, so none
        // can disagree with another about how old an entry is or which
        // shards are fenced. Seeded rather than zero, because every
        // deadline gate reading the clock is vacuous at zero until the
        // resumed chain commits its next block.
        let clock = shard_coordinator.committed_clock().clone();
        let fork_fence = ForkFence::new();
        let mut mempool_coordinator = MempoolCoordinator::with_tx_store(
            local_shard,
            config.mempool_config.clone(),
            Arc::new(TxStore::new()),
            clock.clone(),
            fork_fence.clone(),
        );
        mempool_coordinator.seed_committed(recovered.committed_height);
        // One mirror of the commit-proven remote anchors and one of what
        // counterparts have said, both owned by the shard coordinator:
        // the vote fence and the execution coordinator ask the same
        // questions of them, and two copies could answer differently.
        let execution_coordinator = ExecutionCoordinator::with_shared_stores(
            local_shard,
            Arc::clone(&config.code),
            Arc::new(CrossingIndexSlot::default()),
            recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::clone(shard_coordinator.proven_anchors()),
            Arc::clone(shard_coordinator.mirror()),
            persisted_base,
        );
        let committed_provisions = Arc::clone(shard_coordinator.committed_provisions());
        // The shard's committed-provision window, shared as the proven
        // anchors and mirror above are: both coordinators ask whether the
        // chain already carries a batch, and two copies could answer
        // differently.
        let provisions_coordinator = ProvisionCoordinator::with_config_and_store(
            local_shard,
            config.provision_config,
            Arc::clone(&provision_store),
            committed_provisions,
            clock.clone(),
            fork_fence.clone(),
        );
        Self {
            local_shard,
            derivation: Arc::clone(&config.derivation),
            shard_coordinator,
            execution_coordinator,
            mempool_coordinator,
            provisions_coordinator,
            outbound_provisions: OutboundProvisionTracker::new(provision_store),
            remote_headers_coordinator: RemoteHeaderCoordinator::sharing(
                local_shard,
                clock,
                fork_fence.clone(),
            ),
            now: LocalTimestamp::ZERO,
            handback: PoolHandback::default(),
            stall: CommitStall::default(),
            fork_fence,
        }
    }

    /// Push the current wall-clock into the shard and mempool coordinators
    /// and the mirrored `now`, before any handler runs.
    pub(in crate::replica) const fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
        self.shard_coordinator.set_time(now);
        self.mempool_coordinator.set_time(now);
    }
}
