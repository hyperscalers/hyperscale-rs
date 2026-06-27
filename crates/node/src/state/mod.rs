//! Composite node state machine.
//!
//! [`NodeStateMachine`] is the integration point: a [`BeaconCoordinator`] that
//! every vnode runs, plus an optional [`ShardParticipation`] — the shard
//! coordinators a vnode runs while seated on a shard. A vnode that only follows
//! the beacon carries `shard: None`.
//!
//! All consensus-critical mutation flows through this state machine.
//! Asynchronous concerns (network I/O, thread-pool dispatch, timer scheduling)
//! live on [`NodeHost`](crate::host::NodeHost), which feeds events in and
//! dispatches emitted [`Action`]s.
//!
//! [`handle`](StateMachine::handle) is a thin router: beacon events go to
//! [`beacon`] unconditionally; the shard categories are guarded on the option
//! and dispatched onto [`ShardParticipation`] with the beacon's
//! [`TopologySchedule`] passed as a parameter; the few flows that mutate both
//! halves stay here as orchestrators (see [`orchestration`]).

mod beacon;
mod orchestration;
mod participation;

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
    Block, BlockHeight, LocalTimestamp, ShardId, StateRoot, TopologySchedule, TopologySnapshot,
    ValidatorId,
};
use participation::ShardParticipation;
use tracing::instrument;

/// Combined node state machine.
///
/// The [`BeaconCoordinator`] is the continuous spine every vnode runs. The
/// shard half is optional: present (`Some`) while seated on a shard, absent
/// (`None`) for a vnode that only follows the beacon. View changes are handled
/// implicitly via local round advancement in `ShardCoordinator` (HotStuff-2
/// style).
///
/// The block-sync state machine itself lives on `NodeHost` (in
/// `shard::consensus`); when a synced block is ready to apply, `NodeHost`
/// fires a `BlockSyncReadyToApply` event into this state machine, which routes
/// it to shard consensus.
pub struct NodeStateMachine {
    /// Beacon-chain consensus state (PC + SPC + skip + adoption).
    /// One coordinator per vnode; all vnodes on the same host share an
    /// `Arc<dyn BeaconStorage>` on the runner side via [`ProcessIo`].
    ///
    /// [`ProcessIo`]: crate::process::ProcessIo
    beacon_coordinator: BeaconCoordinator,

    /// Current time.
    now: LocalTimestamp,

    /// This validator's identity.
    me: ValidatorId,

    /// The shard coordinators this vnode runs while seated, or `None` when it
    /// only follows the beacon.
    shard: Option<ShardParticipation>,
}

impl std::fmt::Debug for NodeStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeStateMachine")
            .field("validator", &self.me)
            .field("shard", &self.shard.as_ref().map(|s| s.local_shard))
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl NodeStateMachine {
    /// Create a new node state machine seated on `local_shard`.
    ///
    /// `provision_store`, `tx_store`, `exec_cert_store`, and
    /// `finalized_wave_store` are scoped per shard so same-shard vnodes
    /// converge on one canonical store. Use `RecoveredState::default()`
    /// for a fresh start.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // per-shard-shared stores threaded explicitly
    pub fn new(
        me: ValidatorId,
        local_shard: ShardId,
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
            now: LocalTimestamp::ZERO,
            me,
            shard: Some(ShardParticipation::new(
                me,
                local_shard,
                shard_config,
                recovered,
                mempool_config,
                provision_config,
                provision_store,
                tx_store,
                exec_cert_store,
                finalized_wave_store,
            )),
        }
    }

    /// Create a beacon-following node state machine that runs no shard
    /// consensus (`shard: None`). It folds the beacon, tracks topology, and is
    /// drawable/seatable; the shard half is attached only when it is seated.
    #[must_use]
    pub const fn follower(me: ValidatorId, beacon_coordinator: BeaconCoordinator) -> Self {
        Self {
            beacon_coordinator,
            now: LocalTimestamp::ZERO,
            me,
            shard: None,
        }
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// The seated shard half. Panics if this vnode only follows the beacon —
    /// the shard accessors below are reached only on seated vnodes.
    const fn participation(&self) -> &ShardParticipation {
        match self.shard.as_ref() {
            Some(s) => s,
            None => panic!("shard participation present"),
        }
    }

    /// Get this node's shard.
    #[must_use]
    pub const fn shard_id(&self) -> ShardId {
        self.participation().local_shard
    }

    /// This vnode's seated shard, or `None` when it only follows the beacon.
    /// Used by [`NodeHost::new`](crate::host::NodeHost::new) to split vnodes
    /// into per-shard groups and the beacon-follower pool.
    #[must_use]
    pub fn seated_shard(&self) -> Option<ShardId> {
        self.shard.as_ref().map(|s| s.local_shard)
    }

    /// Get this node's validator identity.
    #[must_use]
    pub const fn validator_id(&self) -> ValidatorId {
        self.me
    }

    /// Get the current topology snapshot.
    #[must_use]
    pub fn topology_snapshot(&self) -> &TopologySnapshot {
        self.beacon_coordinator.current_topology_snapshot()
    }

    /// Get the current topology snapshot as an `Arc`, for sites that
    /// need to clone it into off-thread closures (delegated action
    /// dispatch). The snapshot is identity-agnostic and shared across
    /// every vnode on a host; per-vnode identity travels alongside it
    /// on [`ActionContext`](hyperscale_core::ActionContext).
    #[must_use]
    pub const fn topology_arc(&self) -> &Arc<TopologySnapshot> {
        self.beacon_coordinator.current_topology_snapshot()
    }

    /// Get a reference to the mempool coordinator.
    #[must_use]
    pub const fn mempool_coordinator(&self) -> &MempoolCoordinator {
        &self.participation().mempool_coordinator
    }

    /// Get a reference to the shard consensus coordinator.
    #[must_use]
    pub const fn shard_coordinator(&self) -> &ShardCoordinator {
        &self.participation().shard_coordinator
    }

    /// Get a reference to the beacon coordinator.
    #[must_use]
    pub const fn beacon_coordinator(&self) -> &BeaconCoordinator {
        &self.beacon_coordinator
    }

    /// Get a reference to the execution coordinator.
    #[must_use]
    pub const fn execution_coordinator(&self) -> &ExecutionCoordinator {
        &self.participation().execution_coordinator
    }

    /// Get a reference to the provision coordinator.
    #[must_use]
    pub const fn provisions_coordinator(&self) -> &ProvisionCoordinator {
        &self.participation().provisions_coordinator
    }

    /// Get a reference to the outbound provision tracker.
    #[must_use]
    pub const fn outbound_provisions(&self) -> &OutboundProvisionTracker {
        &self.participation().outbound_provisions
    }

    /// Get a reference to the remote header coordinator.
    #[must_use]
    pub const fn remote_headers_coordinator(&self) -> &RemoteHeaderCoordinator {
        &self.participation().remote_headers_coordinator
    }

    /// Get the last committed JMT root hash (delegated to shard consensus's verification pipeline).
    #[must_use]
    pub const fn last_committed_jmt_root(&self) -> StateRoot {
        self.participation().shard_coordinator.jmt_root()
    }

    /// Initialize the node with a genesis block.
    ///
    /// Returns actions to be processed (e.g., initial timers). Drains both the
    /// shard coordinator's genesis init (when seated) and the beacon
    /// coordinator's `on_startup`, the latter scheduling the first
    /// `BeaconCommitteeStart` timer so the chain bootstraps from a fresh runner.
    ///
    /// `now` seeds the coordinators' clocks before any timer duration is
    /// computed — this runs outside [`StateMachine::handle`], and a split child
    /// seats mid-network-life, where a frozen `ZERO` clock would turn the next
    /// epoch boundary's absolute offset into a relative delay and arm the first
    /// `BeaconCommitteeStart` an entire chain lifetime late.
    pub fn initialize_genesis(&mut self, now: LocalTimestamp, genesis: &Block) -> Vec<Action> {
        self.now = now;
        self.beacon_coordinator.set_now(now);
        let mut actions = Vec::new();
        if let Some(s) = self.shard.as_mut() {
            s.set_time(now);
            actions.extend(s.shard_coordinator.initialize_genesis(genesis));
        }
        actions.extend(self.beacon_coordinator.on_startup());
        actions
    }

    /// Seed the reshape trigger's substate-byte frontier from the genesis
    /// store count — the I/O loop reads it once the genesis block commits.
    /// See [`hyperscale_shard::ShardCoordinator::seed_substate_bytes_frontier`].
    pub const fn seed_substate_bytes_frontier(&mut self, height: BlockHeight, count: u64) {
        if let Some(s) = self.shard.as_mut() {
            s.shard_coordinator
                .seed_substate_bytes_frontier(height, count);
        }
    }

    /// Run `f` against the seated shard half with the beacon's current
    /// [`TopologySchedule`] passed in. Returns an empty action list for a vnode
    /// that only follows the beacon. `self.shard` and `beacon_coordinator` are
    /// disjoint fields, so the schedule borrow and the `&mut` shard borrow
    /// coexist.
    fn with_shard<F>(&mut self, f: F) -> Vec<Action>
    where
        F: FnOnce(&mut ShardParticipation, &TopologySchedule) -> Vec<Action>,
    {
        let Some(s) = self.shard.as_mut() else {
            return Vec::new();
        };
        f(s, self.beacon_coordinator.topology_schedule())
    }
}

impl StateMachine for NodeStateMachine {
    #[instrument(skip(self), fields(
        validator = self.me.inner(),
        shard = ?self.shard.as_ref().map(|s| s.local_shard.inner()),
        event = %event.type_name(),
        height = ?self.shard.as_ref().map(|s| s.shard_coordinator.committed_height().inner()),
    ))]
    #[allow(clippy::too_many_lines)] // single dispatch over ProtocolEvent variants
    fn handle(&mut self, now: LocalTimestamp, event: ProtocolEvent) -> Vec<Action> {
        self.now = now;
        self.beacon_coordinator.set_now(now);
        if let Some(s) = self.shard.as_mut() {
            s.set_time(now);
        }

        let mut actions = match event {
            // ── Timers ───────────────────────────────────────────────────
            ProtocolEvent::CleanupTimer => self.with_shard(ShardParticipation::on_cleanup_timer),
            ProtocolEvent::ViewChangeTimer => {
                self.with_shard(ShardParticipation::on_view_change_timer)
            }

            // ── Cross-coordinator orchestration (drives the beacon too) ────
            ProtocolEvent::BlockCommitted { certified } => self.on_block_committed(&certified),
            ProtocolEvent::RemoteHeaderAdmitted { certified_header } => {
                self.on_remote_header_admitted(&certified_header)
            }

            // ── Shard Consensus ────────────────────────────────────────────
            evt @ (ProtocolEvent::BlockHeaderReceived { .. }
            | ProtocolEvent::QuorumCertificateFormed { .. }
            | ProtocolEvent::VerifiedRemoteHeaderReceived { .. }
            | ProtocolEvent::UnverifiedRemoteHeaderReceived { .. }
            | ProtocolEvent::VerifiedBlockVoteReceived { .. }
            | ProtocolEvent::UnverifiedBlockVoteReceived { .. }
            | ProtocolEvent::VerifiedTimeoutReceived { .. }
            | ProtocolEvent::UnverifiedTimeoutReceived { .. }
            | ProtocolEvent::BlockReadyToCommit { .. }
            | ProtocolEvent::QuorumCertificateResult { .. }
            | ProtocolEvent::QcSignatureVerified { .. }
            | ProtocolEvent::RemoteHeaderQcVerified { .. }
            | ProtocolEvent::TransactionRootVerified { .. }
            | ProtocolEvent::CertificateRootVerified { .. }
            | ProtocolEvent::LocalReceiptRootVerified { .. }
            | ProtocolEvent::ProvisionsRootVerified { .. }
            | ProtocolEvent::ProvisionTxRootsVerified { .. }
            | ProtocolEvent::BeaconWitnessRootVerified { .. }
            | ProtocolEvent::StateRootVerified { .. }
            | ProtocolEvent::ProposalBuilt { .. }
            | ProtocolEvent::BlockPersisted { .. }
            | ProtocolEvent::FinalizedWavesAdmitted { .. }
            | ProtocolEvent::ReadySignalReceived { .. }) => {
                self.with_shard(move |s, sched| s.handle_shard(sched, evt))
            }

            // ── Provisions ───────────────────────────────────────────────
            evt @ (ProtocolEvent::VerifiedProvisionsReceived { .. }
            | ProtocolEvent::UnverifiedProvisionsReceived { .. }
            | ProtocolEvent::StateProvisionsVerified { .. }
            | ProtocolEvent::ProvisionsAdmitted { .. }
            | ProtocolEvent::OutboundProvisionBroadcast { .. }
            | ProtocolEvent::OutboundEcObserved { .. }) => {
                self.with_shard(move |s, sched| s.handle_provisions(sched, evt))
            }

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
            | ProtocolEvent::FinalizedWaveVerified { .. }) => {
                self.with_shard(move |s, sched| s.handle_execution(sched, evt))
            }

            // ── Transactions ─────────────────────────────────────────────
            evt @ (ProtocolEvent::TransactionValidated { .. }
            | ProtocolEvent::TransactionsReceived { .. }
            | ProtocolEvent::TransactionsAdmitted { .. }) => {
                self.with_shard(move |s, sched| s.handle_transaction(sched, evt))
            }

            // ── Sync ─────────────────────────────────────────────────────
            evt @ (ProtocolEvent::BlockSyncReadyToApply { .. }
            | ProtocolEvent::BlockSyncComplete { .. }
            | ProtocolEvent::RemoteHeaderSyncComplete { .. }
            | ProtocolEvent::SettledWavesReconstructed { .. }
            | ProtocolEvent::CommittedStateRestored { .. }) => {
                self.with_shard(move |s, sched| s.handle_sync(sched, evt))
            }

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
            | ProtocolEvent::BeaconSpcInputDwellTimer
            | ProtocolEvent::BeaconBlockPersisted { .. }
            | ProtocolEvent::BeaconBlockSyncReadyToApply { .. }) => self.handle_beacon(evt),
        };

        // Drain any state root verifications that became ready during this
        // event, then re-enter `try_propose` once if a proposal-retry latched.
        // Both touch shard state, so they only run on a seated vnode.
        if let Some(s) = self.shard.as_mut() {
            let local_shard = s.local_shard;
            for ready in s
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
                    claimed_split_child_roots: ready.claimed_split_child_roots,
                    split_child_roots_required: ready.split_child_roots_required,
                    settled_waves_root_required: ready.settled_waves_root_required,
                    claimed_settled_waves_root: ready.claimed_settled_waves_root,
                    parent_weighted_timestamp: ready.parent_weighted_timestamp,
                });
            }

            // If any emitter latched a proposal-retry during this dispatch (or
            // the shard coordinator's verification path unblocked a deferred
            // proposal), re-enter `try_propose` once with fresh transaction
            // selection — avoids stale txs from the original deferral.
            if s.shard_coordinator.take_ready_proposal() {
                let proposal =
                    s.try_event_driven_proposal(self.beacon_coordinator.topology_schedule());
                actions.extend(proposal);
            }
        }

        actions
    }
}
