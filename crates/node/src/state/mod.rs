//! Composite node state machine.
//!
//! [`NodeStateMachine`] composes the per-domain coordinators —
//! [`ShardCoordinator`], [`ExecutionCoordinator`], [`MempoolCoordinator`],
//! [`ProvisionCoordinator`], [`RemoteHeaderCoordinator`] — over a
//! shared [`TopologySnapshot`] into a single deterministic
//! [`StateMachine`] over [`ProtocolEvent`] inputs and [`Action`] outputs.
//!
//! All consensus-critical mutation flows through this state machine.
//! Asynchronous concerns (network I/O, thread-pool dispatch, timer
//! scheduling) live on [`NodeHost`](crate::host::NodeHost), which feeds
//! events in and dispatches emitted [`Action`]s.
//!
//! Submodules route inputs to the appropriate coordinator: [`shard`] for
//! shard consensus events, [`execution`] for wave/EC events, [`mempool`] /
//! [`transactions`] for tx ingress, [`provisions`] for cross-shard state,
//! [`proposal`] for proposer-side construction, [`sync`] for catch-up,
//! and [`timers`] for timeout dispatch.

mod beacon;
mod execution;
mod proposal;
mod provisions;
mod shard;
mod sync;
mod timers;
mod transactions;

#[cfg(test)]
mod test_support;

use std::sync::Arc;

use hyperscale_beacon::coordinator::BeaconCoordinator;
use hyperscale_core::{Action, ProtocolEvent, StateMachine};
use hyperscale_execution::{ExecCertStore, ExecutionCoordinator, FinalizedWaveStore};
use hyperscale_mempool::{MempoolConfig, MempoolCoordinator, TxStore};
use hyperscale_provisions::{
    OutboundProvisionTracker, ProvisionConfig, ProvisionCoordinator, ProvisionStore,
};
use hyperscale_remote_headers::RemoteHeaderCoordinator;
use hyperscale_shard::{ShardConsensusConfig, ShardCoordinator};
use hyperscale_storage::RecoveredState;
use hyperscale_types::{
    Block, LocalTimestamp, ShardGroupId, StateRoot, TopologySnapshot, ValidatorId,
};
use tracing::instrument;

/// Combined node state machine.
///
/// Composes shard consensus, execution, mempool, and provisions into a single state
/// machine. View changes are handled implicitly via local round advancement
/// in `ShardCoordinator` (HotStuff-2 style).
///
/// The block-sync state machine itself lives on `NodeHost` (in
/// `shard_io::sync::block`); when a synced block is ready to apply,
/// `NodeHost` fires a `BlockSyncReadyToApply` event into this state machine,
/// which routes it to shard consensus.
pub struct NodeStateMachine {
    /// Network topology — passed by reference to subsystem methods.
    topology_snapshot: Arc<TopologySnapshot>,

    /// Beacon-chain consensus state (PC + SPC + skip + adoption).
    /// One coordinator per vnode; all vnodes on the same host share an
    /// `Arc<dyn BeaconStorage>` on the runner side via [`ProcessIo`].
    ///
    /// [`ProcessIo`]: crate::process_io::ProcessIo
    beacon_coordinator: BeaconCoordinator,

    /// Shard consensus state (includes implicit round advancement).
    shard_coordinator: ShardCoordinator,

    /// Execution state.
    execution_coordinator: ExecutionCoordinator,

    /// Mempool state.
    mempool_coordinator: MempoolCoordinator,

    /// Provision coordination for cross-shard transactions.
    provisions_coordinator: ProvisionCoordinator,

    /// Retains outbound provisions until the target shard's
    /// execution certificates ACK every transaction they contain.
    outbound_provisions: OutboundProvisionTracker,

    /// Remote block header coordination (single source of truth).
    remote_headers_coordinator: RemoteHeaderCoordinator,

    /// Current time.
    now: LocalTimestamp,

    /// This validator's identity.
    me: ValidatorId,

    /// This validator's home shard.
    local_shard: ShardGroupId,
}

impl std::fmt::Debug for NodeStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeStateMachine")
            .field("validator", &self.me)
            .field("shard_id", &self.local_shard)
            .field("shard_coordinator", &self.shard_coordinator)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl NodeStateMachine {
    /// Create a new node state machine.
    ///
    /// `provision_store`, `tx_store`, `exec_cert_store`, and
    /// `finalized_wave_store` are scoped per shard so same-shard vnodes
    /// converge on one canonical store. Use `RecoveredState::default()`
    /// for a fresh start.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // per-shard-shared stores threaded explicitly
    pub fn new(
        me: ValidatorId,
        local_shard: ShardGroupId,
        topology_snapshot: Arc<TopologySnapshot>,
        shard_config: &ShardConsensusConfig,
        recovered: RecoveredState,
        beacon_coordinator: BeaconCoordinator,
        mempool_config: MempoolConfig,
        provision_config: ProvisionConfig,
        provision_store: Arc<ProvisionStore>,
        tx_store: Arc<TxStore>,
        exec_cert_store: Arc<ExecCertStore>,
        finalized_wave_store: Arc<FinalizedWaveStore>,
    ) -> Self {
        Self {
            beacon_coordinator,
            shard_coordinator: ShardCoordinator::new(
                me,
                local_shard,
                shard_config.clone(),
                recovered,
            ),
            execution_coordinator: ExecutionCoordinator::with_shared_stores(
                me,
                local_shard,
                exec_cert_store,
                finalized_wave_store,
            ),
            mempool_coordinator: MempoolCoordinator::with_tx_store(
                local_shard,
                mempool_config,
                tx_store,
            ),
            provisions_coordinator: ProvisionCoordinator::with_config_and_store(
                local_shard,
                provision_config,
                Arc::clone(&provision_store),
            ),
            outbound_provisions: OutboundProvisionTracker::new(provision_store),
            remote_headers_coordinator: RemoteHeaderCoordinator::new(local_shard),
            topology_snapshot,
            now: LocalTimestamp::ZERO,
            me,
            local_shard,
        }
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Get this node's shard.
    #[must_use]
    pub const fn shard_id(&self) -> ShardGroupId {
        self.local_shard
    }

    /// Get this node's validator identity.
    #[must_use]
    pub const fn validator_id(&self) -> ValidatorId {
        self.me
    }

    /// Get the current topology snapshot.
    #[must_use]
    pub fn topology(&self) -> &TopologySnapshot {
        &self.topology_snapshot
    }

    /// Get the current topology snapshot as an `Arc`, for sites that
    /// need to clone it into off-thread closures (delegated action
    /// dispatch). The snapshot is identity-agnostic and shared across
    /// every vnode on a host; per-vnode identity travels alongside it
    /// on [`ActionContext`](hyperscale_core::ActionContext).
    #[must_use]
    pub const fn topology_arc(&self) -> &Arc<TopologySnapshot> {
        &self.topology_snapshot
    }

    /// Get a reference to the mempool coordinator.
    #[must_use]
    pub const fn mempool_coordinator(&self) -> &MempoolCoordinator {
        &self.mempool_coordinator
    }

    /// Get a reference to the shard consensus coordinator.
    #[must_use]
    pub const fn shard_coordinator(&self) -> &ShardCoordinator {
        &self.shard_coordinator
    }

    /// Get a reference to the execution coordinator.
    #[must_use]
    pub const fn execution_coordinator(&self) -> &ExecutionCoordinator {
        &self.execution_coordinator
    }

    /// Get a reference to the provision coordinator.
    #[must_use]
    pub const fn provisions_coordinator(&self) -> &ProvisionCoordinator {
        &self.provisions_coordinator
    }

    /// Get a reference to the outbound provision tracker.
    #[must_use]
    pub const fn outbound_provisions(&self) -> &OutboundProvisionTracker {
        &self.outbound_provisions
    }

    /// Get a reference to the remote header coordinator.
    #[must_use]
    pub const fn remote_headers_coordinator(&self) -> &RemoteHeaderCoordinator {
        &self.remote_headers_coordinator
    }

    /// Get the last committed JMT root hash (delegated to shard consensus's verification pipeline).
    #[must_use]
    pub const fn last_committed_jmt_root(&self) -> StateRoot {
        self.shard_coordinator.jmt_root()
    }

    /// Initialize the node with a genesis block.
    ///
    /// Returns actions to be processed (e.g., initial timers). Drains
    /// both the shard coordinator's genesis init and the beacon
    /// coordinator's `on_startup`, the latter scheduling the first
    /// `BeaconCommitteeStart` timer so the chain bootstraps from a
    /// fresh runner.
    pub fn initialize_genesis(&mut self, genesis: &Block) -> Vec<Action> {
        let mut actions = self.shard_coordinator.initialize_genesis(genesis);
        actions.extend(self.beacon_coordinator.on_startup());
        actions
    }
}

impl StateMachine for NodeStateMachine {
    #[instrument(skip(self), fields(
        validator = self.me.inner(),
        shard = self.local_shard.inner(),
        event = %event.type_name(),
        height = self.shard_coordinator.committed_height().inner(),
    ))]
    #[allow(clippy::too_many_lines)] // single dispatch over ProtocolEvent variants
    fn handle(&mut self, now: LocalTimestamp, event: ProtocolEvent) -> Vec<Action> {
        self.now = now;
        self.shard_coordinator.set_time(now);
        let mut actions = match event {
            // ── Timers ───────────────────────────────────────────────────
            ProtocolEvent::CleanupTimer => self.on_cleanup_timer(),
            ProtocolEvent::ViewChangeTimer => self.on_view_change_timer(),

            // ── Shard Consensus ────────────────────────────────────────────
            evt @ (ProtocolEvent::BlockHeaderReceived { .. }
            | ProtocolEvent::QuorumCertificateFormed { .. }
            | ProtocolEvent::VerifiedRemoteHeaderReceived { .. }
            | ProtocolEvent::UnverifiedRemoteHeaderReceived { .. }
            | ProtocolEvent::VerifiedBlockVoteReceived { .. }
            | ProtocolEvent::UnverifiedBlockVoteReceived { .. }
            | ProtocolEvent::BlockReadyToCommit { .. }
            | ProtocolEvent::QuorumCertificateResult { .. }
            | ProtocolEvent::QcSignatureVerified { .. }
            | ProtocolEvent::RemoteHeaderQcVerified { .. }
            | ProtocolEvent::RemoteHeaderAdmitted { .. }
            | ProtocolEvent::TransactionRootVerified { .. }
            | ProtocolEvent::CertificateRootVerified { .. }
            | ProtocolEvent::LocalReceiptRootVerified { .. }
            | ProtocolEvent::ProvisionsRootVerified { .. }
            | ProtocolEvent::ProvisionTxRootsVerified { .. }
            | ProtocolEvent::BeaconWitnessRootVerified { .. }
            | ProtocolEvent::StateRootVerified { .. }
            | ProtocolEvent::ProposalBuilt { .. }
            | ProtocolEvent::BlockCommitted { .. }
            | ProtocolEvent::BlockPersisted { .. }
            | ProtocolEvent::FinalizedWavesAdmitted { .. }
            | ProtocolEvent::ReadySignalReceived { .. }) => self.handle_shard(evt),

            // ── Provisions ───────────────────────────────────────────────
            evt @ (ProtocolEvent::VerifiedProvisionsReceived { .. }
            | ProtocolEvent::UnverifiedProvisionsReceived { .. }
            | ProtocolEvent::StateProvisionsVerified { .. }
            | ProtocolEvent::ProvisionsAdmitted { .. }
            | ProtocolEvent::OutboundProvisionBroadcast { .. }
            | ProtocolEvent::OutboundEcObserved { .. }) => self.handle_provisions(evt),

            // ── Execution ────────────────────────────────────────────────
            evt @ (ProtocolEvent::ExecutionBatchCompleted { .. }
            | ProtocolEvent::VerifiedExecutionVoteReceived { .. }
            | ProtocolEvent::UnverifiedExecutionVoteReceived { .. }
            | ProtocolEvent::ExecutionVotesVerifiedAndAggregated { .. }
            | ProtocolEvent::ExecutionCertificateAggregated { .. }
            | ProtocolEvent::ExecutionCertificatesReceived { .. }
            | ProtocolEvent::ExecutionCertificateSignatureVerified { .. }
            | ProtocolEvent::ExecutionCertificateAdmitted { .. }
            | ProtocolEvent::FinalizedWavesReceived { .. }
            | ProtocolEvent::FinalizedWaveVerified { .. }) => self.handle_execution(evt),

            // ── Transactions ─────────────────────────────────────────────
            evt @ (ProtocolEvent::TransactionValidated { .. }
            | ProtocolEvent::TransactionsReceived { .. }
            | ProtocolEvent::TransactionsAdmitted { .. }) => self.handle_transaction(evt),

            // ── Sync ─────────────────────────────────────────────────────
            evt @ (ProtocolEvent::BlockSyncReadyToApply { .. }
            | ProtocolEvent::BlockSyncComplete { .. }
            | ProtocolEvent::RemoteHeaderSyncComplete { .. }
            | ProtocolEvent::CommittedStateRestored { .. }) => self.handle_sync(evt),

            // ── Beacon ───────────────────────────────────────────────────
            evt @ (ProtocolEvent::UnverifiedPcVote1Received { .. }
            | ProtocolEvent::UnverifiedPcVote2Received { .. }
            | ProtocolEvent::UnverifiedPcVote3Received { .. }
            | ProtocolEvent::VerifiedPcVote1Received { .. }
            | ProtocolEvent::VerifiedPcVote2Received { .. }
            | ProtocolEvent::VerifiedPcVote3Received { .. }
            | ProtocolEvent::SpcNewViewReceived { .. }
            | ProtocolEvent::SpcNewCommitReceived { .. }
            | ProtocolEvent::UnverifiedSpcEmptyViewReceived { .. }
            | ProtocolEvent::VerifiedSpcEmptyViewReceived { .. }
            | ProtocolEvent::BeaconBlockReceived { .. }
            | ProtocolEvent::UnverifiedBeaconProposalReceived { .. }
            | ProtocolEvent::VerifiedBeaconProposalReceived { .. }
            | ProtocolEvent::UnverifiedSkipRequestReceived { .. }
            | ProtocolEvent::VerifiedSkipRequestReceived { .. }
            | ProtocolEvent::SkipCertReceived { .. }
            | ProtocolEvent::ShardWitnessesReceived { .. }
            | ProtocolEvent::BeaconProposalFetched { .. }
            | ProtocolEvent::BeaconBlockVerified { .. }
            | ProtocolEvent::SkipRequestVerified { .. }
            | ProtocolEvent::PcVote1Verified { .. }
            | ProtocolEvent::PcVote2Verified { .. }
            | ProtocolEvent::PcVote3Verified { .. }
            | ProtocolEvent::SpcNewViewVerified { .. }
            | ProtocolEvent::SpcNewCommitVerified { .. }
            | ProtocolEvent::SpcEmptyViewVerified { .. }
            | ProtocolEvent::BeaconCommitteeStartTimer
            | ProtocolEvent::BeaconSkipTimer
            | ProtocolEvent::BeaconSpcViewTimer
            | ProtocolEvent::BeaconBlockPersisted { .. }) => self.handle_beacon(evt),
        };

        // Drain any state root verifications that became ready during this event.
        let local_shard = self.local_shard;
        for ready in self
            .shard_coordinator
            .drain_ready_state_root_verifications(local_shard)
        {
            actions.push(Action::VerifyStateRoot {
                block_hash: ready.block_hash,
                parent_block_hash: ready.parent_block_hash,
                parent_state_root: ready.parent_state_root,
                parent_block_height: ready.parent_block_height,
                expected_root: ready.expected_root,
                expected_local_receipt_root: ready.expected_local_receipt_root,
                finalized_waves: ready.finalized_waves,
                block_height: ready.block_height,
            });
        }

        // If any emitter latched a proposal-retry during this dispatch (or
        // the shard coordinator's verification path unblocked a deferred proposal), re-enter
        // `try_propose` once with fresh transaction selection — avoids
        // stale txs from the original deferral.
        if self.shard_coordinator.take_ready_proposal() {
            actions.extend(self.try_event_driven_proposal());
        }

        actions
    }
}
