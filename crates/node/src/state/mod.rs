//! Composite node state machine.
//!
//! [`NodeStateMachine`] is a replica's integration point: the shard,
//! execution, mempool, provisions and remote-header coordinators it runs
//! for its shard ([`ShardParticipation`]), and the beacon schedule they
//! read. The beacon itself runs once per host, on its beacon loop: what the
//! replica commits, certifies and admits goes there as a
//! [`BeaconInput`], and each schedule the beacon folds comes back as
//! [`ProtocolEvent::BeaconBlockPersisted`].
//!
//! All consensus-critical mutation flows through this state machine.
//! Asynchronous concerns (network I/O, thread-pool dispatch, timer scheduling)
//! live on [`NodeHost`](crate::host::NodeHost), which feeds events in and
//! dispatches emitted [`Action`]s.
//!
//! [`handle`](StateMachine::handle) is a thin router: each category is
//! dispatched onto [`ShardParticipation`] with the held [`TopologySchedule`]
//! passed as a parameter; the flows that also report to the beacon stay here
//! as orchestrators (see [`orchestration`]).

mod orchestration;
mod participation;

#[cfg(test)]
mod test_support;

use std::sync::Arc;

use hyperscale_core::{Action, ProtocolEvent, StateMachine};
use hyperscale_engine::CodeAvailability;
use hyperscale_execution::{
    CrossingIndexSlot, ExecCertStore, ExecutionCoordinator, FinalizationStore,
};
use hyperscale_mempool::{MempoolConfig, MempoolCoordinator, TxStore};
use hyperscale_provisions::{
    OutboundProvisionTracker, ProvisionConfig, ProvisionCoordinator, ProvisionStore,
};
use hyperscale_remote_headers::RemoteHeaderCoordinator;
use hyperscale_shard::{ShardConsensusConfig, ShardCoordinator};
use hyperscale_storage::RecoveredState;
use hyperscale_types::{
    Block, BlockHeight, Derivation, Epoch, LocalTimestamp, ShardId, StandingAnswers, StateRoot,
    TopologySchedule, TopologySnapshot, ValidatorId, Verifier,
};
use participation::ShardParticipation;
use tracing::instrument;

use crate::event::BeaconInput;

/// A replica's state machine: the coordinators it runs for its shard,
/// over the beacon schedule it holds.
///
/// View changes are handled implicitly via local round advancement in
/// `ShardCoordinator` (HotStuff-2 style).
///
/// The block-sync state machine itself lives on `NodeHost` (in
/// `shard::consensus`); when a synced block is ready to apply, `NodeHost`
/// fires a `BlockSyncReadyToApply` event into this state machine, which routes
/// it to shard consensus.
pub struct NodeStateMachine {
    /// The schedule the coordinators read, and the epoch the beacon
    /// folded it at. It changes only between events, when a
    /// `BeaconBlockPersisted` carries a newer one.
    schedule: Arc<TopologySchedule>,
    schedule_epoch: Epoch,

    /// Current time.
    now: LocalTimestamp,

    /// The coordinators this replica runs for its shard.
    shard: ShardParticipation,

    /// What the last event reported to the beacon, for the loop to send
    /// on.
    beacon_inputs: Vec<BeaconInput>,
}

impl std::fmt::Debug for NodeStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeStateMachine")
            .field("shard", &self.shard.local_shard)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl NodeStateMachine {
    /// Create a replica's state machine for `me` on `local_shard`, over
    /// `schedule`, the schedule the beacon folded at `schedule_epoch`.
    ///
    /// `provision_store`, `tx_store`, `exec_cert_store`, and
    /// `finalization_store` are scoped per shard so same-shard vnodes
    /// converge on one canonical store. Use `RecoveredState::default()`
    /// for a fresh start.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // per-shard-shared stores threaded explicitly
    pub fn new(
        me: ValidatorId,
        verifier: Arc<dyn Verifier>,
        derivation: Arc<dyn Derivation>,
        code: Arc<dyn CodeAvailability>,
        local_shard: ShardId,
        shard_config: &ShardConsensusConfig,
        recovered: &RecoveredState,
        schedule: Arc<TopologySchedule>,
        schedule_epoch: Epoch,
        mempool_config: MempoolConfig,
        provision_config: ProvisionConfig,
        provision_store: Arc<ProvisionStore>,
        tx_store: Arc<TxStore>,
        exec_cert_store: Arc<ExecCertStore>,
        finalization_store: Arc<FinalizationStore>,
        crossing_index: Arc<CrossingIndexSlot>,
    ) -> Self {
        let mut shard = ShardParticipation::new(
            verifier,
            derivation,
            code,
            me,
            local_shard,
            shard_config,
            recovered,
            mempool_config,
            provision_config,
            provision_store,
            tx_store,
            exec_cert_store,
            finalization_store,
            crossing_index,
        );
        shard.shard_coordinator.latch_dissolution(&schedule);
        Self {
            schedule,
            schedule_epoch,
            now: LocalTimestamp::ZERO,
            shard,
            beacon_inputs: Vec::new(),
        }
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Get this node's shard.
    #[must_use]
    pub(crate) const fn shard_id(&self) -> ShardId {
        self.shard.local_shard
    }

    /// The schedule the replica holds.
    #[must_use]
    pub const fn schedule(&self) -> &Arc<TopologySchedule> {
        &self.schedule
    }

    /// The epoch the beacon folded the held schedule at.
    #[must_use]
    pub(crate) const fn schedule_epoch(&self) -> Epoch {
        self.schedule_epoch
    }

    /// Get the current topology snapshot.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn topology_snapshot(&self) -> &TopologySnapshot {
        self.schedule.head()
    }

    /// Get the current topology snapshot as an `Arc`, for sites that
    /// need to clone it into off-thread closures (delegated action
    /// dispatch). The snapshot is identity-agnostic and shared across
    /// every vnode on a host; per-vnode identity travels alongside it
    /// on [`ActionContext`](hyperscale_core::ActionContext).
    #[must_use]
    pub(crate) fn topology_arc(&self) -> &Arc<TopologySnapshot> {
        self.schedule.head()
    }

    /// Get a reference to the mempool coordinator.
    #[must_use]
    pub const fn mempool_coordinator(&self) -> &MempoolCoordinator {
        &self.shard.mempool_coordinator
    }

    /// Get a reference to the shard consensus coordinator.
    #[must_use]
    pub const fn shard_coordinator(&self) -> &ShardCoordinator {
        &self.shard.shard_coordinator
    }

    /// Tell the shard coordinator which validators this host seats in its
    /// shard.
    pub(crate) fn set_host_seats(&mut self, seats: &[ValidatorId]) {
        self.shard
            .shard_coordinator
            .set_host_seats(seats.iter().copied());
    }

    /// Get a reference to the execution coordinator.
    #[must_use]
    pub const fn execution_coordinator(&self) -> &ExecutionCoordinator {
        &self.shard.execution_coordinator
    }

    /// Get a reference to the provision coordinator.
    #[must_use]
    pub(crate) const fn provisions_coordinator(&self) -> &ProvisionCoordinator {
        &self.shard.provisions_coordinator
    }

    /// Get a reference to the outbound provision tracker.
    #[must_use]
    pub const fn outbound_provisions(&self) -> &OutboundProvisionTracker {
        &self.shard.outbound_provisions
    }

    /// Get a reference to the remote header coordinator.
    #[must_use]
    pub const fn remote_headers_coordinator(&self) -> &RemoteHeaderCoordinator {
        &self.shard.remote_headers_coordinator
    }

    /// Get the last committed JMT root hash (delegated to shard consensus's verification pipeline).
    #[must_use]
    pub const fn last_committed_jmt_root(&self) -> StateRoot {
        self.shard.shard_coordinator.jmt_root()
    }

    /// Take what the last events reported to the beacon.
    pub(crate) fn take_beacon_inputs(&mut self) -> Vec<BeaconInput> {
        std::mem::take(&mut self.beacon_inputs)
    }

    /// Initialize the node with a genesis block.
    ///
    /// Returns actions to be processed (e.g., initial timers).
    ///
    /// `now` seeds the coordinators' clocks before any timer duration is
    /// computed — this runs outside [`StateMachine::handle`].
    pub(crate) fn initialize_genesis(
        &mut self,
        now: LocalTimestamp,
        genesis: &Block,
    ) -> Vec<Action> {
        self.now = now;
        self.shard.set_time(now);
        self.shard.shard_coordinator.initialize_genesis(genesis)
    }

    /// Seed the reshape trigger's substate-byte frontier from the genesis
    /// store count — the I/O loop reads it once the genesis block commits.
    /// See [`hyperscale_shard::ShardCoordinator::seed_substate_bytes_frontier`].
    pub(crate) const fn seed_substate_bytes_frontier(&mut self, height: BlockHeight, count: u64) {
        self.shard
            .shard_coordinator
            .seed_substate_bytes_frontier(height, count);
    }

    /// Seed the answer count at a chain's genesis. See
    /// [`hyperscale_shard::ShardCoordinator::seed_standing_answers`].
    pub(crate) fn seed_standing_answers(&mut self, height: BlockHeight, count: StandingAnswers) {
        self.shard
            .shard_coordinator
            .seed_standing_answers(&self.schedule, height, count);
    }

    /// Whether this vnode sits in its shard's committee.
    /// See [`hyperscale_shard::ShardCoordinator::seated_to_vote`].
    pub(crate) fn seated_to_vote(&self) -> bool {
        self.shard.shard_coordinator.seated_to_vote(&self.schedule)
    }

    /// Tell execution how far the store this seat reads is written, as
    /// the loop taking the seat finds it. See
    /// [`ExecutionCoordinator::seat_on_persisted_base`].
    pub(crate) fn seat_on_persisted_base(&mut self, height: BlockHeight) {
        self.shard
            .execution_coordinator
            .seat_on_persisted_base(height);
    }

    /// Run `f` against the shard half with the held [`TopologySchedule`]
    /// passed in.
    fn on_shard<F>(&mut self, f: F) -> Vec<Action>
    where
        F: FnOnce(&mut ShardParticipation, &TopologySchedule) -> Vec<Action>,
    {
        f(&mut self.shard, &self.schedule)
    }

    /// Hold `schedule`, folded at `epoch`, if it is newer than the one
    /// held. The replica latches its dissolution against the schedule it
    /// gives up and then against the new one, so a reading either showed
    /// survives the eviction of the windows it rested on.
    fn install_schedule(&mut self, epoch: Epoch, schedule: Arc<TopologySchedule>) {
        if epoch <= self.schedule_epoch {
            return;
        }
        let coordinator = &mut self.shard.shard_coordinator;
        coordinator.latch_dissolution(&self.schedule);
        coordinator.latch_dissolution(&schedule);
        self.schedule = schedule;
        self.schedule_epoch = epoch;
    }
}

impl StateMachine for NodeStateMachine {
    #[instrument(skip(self), fields(
        shard = self.shard.local_shard.inner(),
        event = %event.type_name(),
        height = self.shard.shard_coordinator.committed_height().inner(),
    ))]
    #[allow(clippy::too_many_lines)] // single dispatch over ProtocolEvent variants
    fn handle(&mut self, now: LocalTimestamp, event: ProtocolEvent) -> Vec<Action> {
        self.now = now;
        self.shard.set_time(now);

        let mut inputs = Vec::new();
        let mut actions = match event {
            // ── Timers ───────────────────────────────────────────────────
            ProtocolEvent::CleanupTimer => self.on_shard(ShardParticipation::on_cleanup_timer),
            ProtocolEvent::ViewChangeTimer => {
                self.on_shard(ShardParticipation::on_view_change_timer)
            }
            ProtocolEvent::ProposalPaceTimer => {
                self.on_shard(ShardParticipation::try_event_driven_proposal)
            }
            ProtocolEvent::ProposalFetchTimer => {
                self.on_shard(|s, _| s.shard_coordinator.fetch_overdue_proposals())
            }

            // ── Cross-coordinator orchestration (drives the beacon too) ────
            ProtocolEvent::BlockCommitted {
                certified,
                committee_anchor,
            } => self.on_block_committed(&certified, committee_anchor, &mut inputs),
            ProtocolEvent::LocalBlockCertified { certified_header } => {
                inputs.push(BeaconInput::CertifiedHeader {
                    header: certified_header,
                });
                Vec::new()
            }
            ProtocolEvent::RemoteHeaderAdmitted { certified_header } => {
                self.on_remote_header_admitted(certified_header, &mut inputs)
            }
            ProtocolEvent::RemoteHeaderCommitted { certified_header } => {
                self.on_remote_header_committed(&certified_header, &mut inputs)
            }

            // ── Shard Consensus ────────────────────────────────────────────
            evt @ (ProtocolEvent::BlockHeaderReceived { .. }
            | ProtocolEvent::QuorumCertificateFormed { .. }
            | ProtocolEvent::VerifiedRemoteHeaderReceived { .. }
            | ProtocolEvent::UnverifiedRemoteHeaderReceived { .. }
            | ProtocolEvent::RemoteHeadersBelowFloor { .. }
            | ProtocolEvent::VerifiedBlockVoteReceived { .. }
            | ProtocolEvent::UnverifiedBlockVoteReceived { .. }
            | ProtocolEvent::VerifiedTimeoutReceived { .. }
            | ProtocolEvent::UnverifiedTimeoutReceived { .. }
            | ProtocolEvent::QcAnnouncementReceived { .. }
            | ProtocolEvent::BlockReadyToCommit { .. }
            | ProtocolEvent::QuorumCertificateResult { .. }
            | ProtocolEvent::QcSignatureVerified { .. }
            | ProtocolEvent::RemoteHeaderQcVerified { .. }
            | ProtocolEvent::BlockCheckCompleted { .. }
            | ProtocolEvent::ProposalBuilt { .. }
            | ProtocolEvent::BlockPersisted { .. }
            | ProtocolEvent::FinalizationsAdmitted { .. }
            | ProtocolEvent::ReadySignalReceived { .. }
            | ProtocolEvent::UnverifiedShardForkProofReceived { .. }
            | ProtocolEvent::CommitProofNeeded { .. }) => {
                self.on_shard(move |s, sched| s.handle_shard(sched, evt))
            }

            // A fork is proven — locally assembled from verified headers, or
            // a peer's proof that just verified. The shard layer engages its
            // local provisional fence and re-gossips, and the proof goes into
            // the beacon observation buffer once the arm has run, so the next
            // beacon proposal funnels it into a fork-caused recovery.
            ProtocolEvent::ShardForkDetected { proof } => {
                inputs.push(BeaconInput::ForkProof(proof.clone()));
                let evt = ProtocolEvent::ShardForkDetected { proof };
                self.on_shard(move |s, sched| s.handle_shard(sched, evt))
            }
            ProtocolEvent::ShardForkProofVerified { proof, verified } => {
                if verified {
                    inputs.push(BeaconInput::ForkProof(proof.clone()));
                }
                let evt = ProtocolEvent::ShardForkProofVerified { proof, verified };
                self.on_shard(move |s, sched| s.handle_shard(sched, evt))
            }

            // A double-vote pair the local vote keeper caught goes to the
            // beacon, whose next proposal carries it to conviction.
            ProtocolEvent::ShardVoteEquivocationDetected { evidence } => {
                inputs.push(BeaconInput::VoteEquivocation { evidence });
                Vec::new()
            }

            // ── Provisions ───────────────────────────────────────────────
            evt @ (ProtocolEvent::VerifiedProvisionsReceived { .. }
            | ProtocolEvent::UnverifiedProvisionsReceived { .. }
            | ProtocolEvent::CrossingReadingsReceived { .. }
            | ProtocolEvent::StateProvisionsVerified { .. }
            | ProtocolEvent::ProvisionsAdmitted { .. }
            | ProtocolEvent::OutboundProvisionBroadcast { .. }
            | ProtocolEvent::OutboundEcObserved { .. }) => {
                self.on_shard(move |s, sched| s.handle_provisions(sched, evt))
            }

            // ── Execution ────────────────────────────────────────────────
            evt @ (ProtocolEvent::ExecutionBatchCompleted { .. }
            | ProtocolEvent::ExecutionBatchUnavailable { .. }
            | ProtocolEvent::ExecutionVoteReceived { .. }
            | ProtocolEvent::ExecutionVotesVerifiedAndAggregated { .. }
            | ProtocolEvent::ExecutionCertificateAggregated { .. }
            | ProtocolEvent::ExecutionCertificatesReceived { .. }
            | ProtocolEvent::ExecutionCertificateSignatureVerified { .. }
            | ProtocolEvent::ExecutionCertificateAdmitted { .. }
            | ProtocolEvent::FinalizationsReceived { .. }
            | ProtocolEvent::FinalizationVerified { .. }
            | ProtocolEvent::LegsHalfBuilt { .. }) => {
                self.on_shard(move |s, sched| s.handle_execution(sched, evt))
            }

            // ── Transactions ─────────────────────────────────────────────
            evt @ (ProtocolEvent::TransactionValidated { .. }
            | ProtocolEvent::TransactionsReceived { .. }
            | ProtocolEvent::TransactionsAdmitted { .. }
            | ProtocolEvent::TransactionsResolved { .. }) => {
                self.on_shard(move |s, sched| s.handle_transaction(sched, evt))
            }

            // ── Sync ─────────────────────────────────────────────────────
            evt @ (ProtocolEvent::BlockSyncReadyToApply { .. }
            | ProtocolEvent::BlockSyncComplete { .. }
            | ProtocolEvent::RemoteHeaderSyncComplete { .. }
            | ProtocolEvent::SettledTxsReconstructed { .. }
            | ProtocolEvent::FetchedStateProofVerified { .. }
            | ProtocolEvent::FetchedVerdictProofVerified { .. }) => {
                self.on_shard(move |s, sched| s.handle_sync(sched, evt))
            }

            evt @ ProtocolEvent::CommittedStateRestored { .. } => {
                self.on_shard(move |s, sched| s.handle_sync(sched, evt))
            }

            // ── Beacon ───────────────────────────────────────────────────
            // A schedule the beacon folded: held if newer, then the shard
            // coordinators replay what waited on the epoch.
            ProtocolEvent::BeaconBlockPersisted { epoch, schedule } => {
                self.install_schedule(epoch, schedule);
                self.on_shard(ShardParticipation::on_beacon_block_persisted)
            }

            // The beacon runs on the host's beacon loop, never on a replica.
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
            | ProtocolEvent::BeaconProposalReceived { .. }
            | ProtocolEvent::UnverifiedRatifyVoteReceived { .. }
            | ProtocolEvent::VerifiedRatifyVoteReceived { .. }
            | ProtocolEvent::BeaconCandidateReceived { .. }
            | ProtocolEvent::BeaconCandidateVerified { .. }
            | ProtocolEvent::ShardWitnessesReceived { .. }
            | ProtocolEvent::BeaconProposalFetched { .. }
            | ProtocolEvent::BeaconBlockVerified { .. }
            | ProtocolEvent::RatifyVoteVerified { .. }
            | ProtocolEvent::PcVote1Verified { .. }
            | ProtocolEvent::PcVote2Verified { .. }
            | ProtocolEvent::PcVote3Verified { .. }
            | ProtocolEvent::SpcNewViewVerified { .. }
            | ProtocolEvent::SpcNewCommitVerified { .. }
            | ProtocolEvent::SpcEmptyViewVerified { .. }
            | ProtocolEvent::BeaconCommitteeStartTimer
            | ProtocolEvent::BeaconRatifyTimer
            | ProtocolEvent::BeaconSpcViewTimer
            | ProtocolEvent::BeaconSpcInputDwellTimer
            | ProtocolEvent::BeaconBlockSyncReadyToApply { .. }
            | ProtocolEvent::UnverifiedShardVoteEquivocationReceived { .. }
            | ProtocolEvent::ShardVoteEquivocationVerified { .. }) => {
                tracing::warn!(
                    event = evt.type_name(),
                    "a beacon event reached a replica — dropping"
                );
                Vec::new()
            }
        };

        self.beacon_inputs.extend(inputs);

        // Drain any state root verifications that became ready during this
        // event, then re-enter `try_propose` once if a proposal-retry latched.
        {
            let s = &mut self.shard;
            let topology_schedule = &self.schedule;
            for ready in s.shard_coordinator.drain_ready_state_root_verifications() {
                actions.push(Action::VerifyStateRoot {
                    block_hash: ready.block_hash,
                    parent_block_hash: ready.parent_block_hash,
                    parent_state_root: ready.parent_state_root,
                    parent_block_height: ready.parent_block_height,
                    expected_root: ready.expected_root,
                    finalizations: ready.finalizations,
                    creations: ready.creations,
                    block_height: ready.block_height,
                    claimed_split_child_roots: ready.claimed_split_child_roots,
                    split_child_roots_required: ready.split_child_roots_required,
                    terminal_settled_txs_required: ready.terminal_settled_txs_required,
                    claimed_terminal_settled_txs: ready.claimed_terminal_settled_txs,
                    parent_weighted_timestamp: ready.parent_weighted_timestamp,
                    settled_txs_window_floor: ready.settled_txs_window_floor,
                    parent_sweep_frontier: ready.parent_sweep_frontier,
                    claimed_sweep_frontier: ready.claimed_sweep_frontier,
                    frontier: ready.frontier,
                    members: ready.members,
                    parent_judgement: ready.parent_judgement,
                    state_claims: ready.state_claims,
                    transactions: ready.transactions,
                });
            }

            // If any emitter latched a proposal-retry during this dispatch (or
            // the shard coordinator's verification path unblocked a deferred
            // proposal), re-enter `try_propose` once with fresh transaction
            // selection — avoids stale txs from the original deferral.
            if s.shard_coordinator.take_ready_proposal() {
                actions.extend(s.try_event_driven_proposal(topology_schedule));
            }

            // Whatever this dispatch wrote into the evidence the vote
            // fence reads — a counterpart's word, a settled set, a proven
            // anchor, a predecessor's answer — re-drives the votes that
            // deferred for want of it, once, here, so no writer has to
            // know which votes were waiting.
            if s.shard_coordinator.take_fence_evidence_advanced() {
                actions.extend(s.shard_coordinator.redrive_pending_votes(topology_schedule));
            }
        }

        actions
    }
}
