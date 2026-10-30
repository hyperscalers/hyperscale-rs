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
//! [`handle`](StateMachine::handle) is one exhaustive match over
//! [`ProtocolEvent`]: each arm calls the coordinator or
//! [`ShardParticipation`] handler for its variant with the held
//! [`TopologySchedule`] passed as a parameter; the flows that also report
//! to the beacon stay here as orchestrators (see [`orchestration`]).

mod config;
mod orchestration;
mod participation;

#[cfg(test)]
mod test_support;

use std::sync::Arc;

pub use config::{AttachedSigner, ReplicaConfig};
use hyperscale_core::{Action, ProtocolEvent, StateMachine};
use hyperscale_execution::ExecutionCoordinator;
use hyperscale_mempool::MempoolCoordinator;
#[cfg(test)]
use hyperscale_provisions::OutboundProvisionTracker;
use hyperscale_provisions::ProvisionCoordinator;
use hyperscale_remote_headers::RemoteHeaderCoordinator;
use hyperscale_shard::{SettledTxSet, ShardCoordinator};
use hyperscale_storage::RecoveredState;
use hyperscale_types::{
    Block, BlockHeight, Epoch, LocalTimestamp, Round, SafeVoteRegisters, ShardId, StandingAnswers,
    StateRoot, TopologySchedule, TopologySnapshot, ValidatorId,
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
            .finish_non_exhaustive()
    }
}

impl NodeStateMachine {
    /// Create a replica's state machine on `local_shard` with no signer,
    /// built with `config`, over `schedule`, the schedule the beacon folded
    /// at `schedule_epoch`. Each validator it signs for joins through
    /// [`Self::attach_signer`].
    ///
    /// `persisted_base` is how far the store under the replica's tick
    /// chain is written. Use `RecoveredState::default()` for a fresh
    /// start.
    #[must_use]
    pub(crate) fn new(
        config: &ReplicaConfig,
        local_shard: ShardId,
        recovered: &RecoveredState,
        (schedule, schedule_epoch): (Arc<TopologySchedule>, Epoch),
        persisted_base: BlockHeight,
    ) -> Self {
        let mut shard = ShardParticipation::new(
            config,
            local_shard,
            recovered,
            schedule.windows().origin(),
            persisted_base,
        );
        shard.shard_coordinator.latch_dissolution(&schedule);
        Self {
            schedule,
            schedule_epoch,
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
    #[cfg(test)]
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
    /// every loop on a host; the signing identity travels alongside it
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
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn outbound_provisions(&self) -> &OutboundProvisionTracker {
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
        genesis_bytes: u64,
    ) -> Vec<Action> {
        self.shard.set_time(now);
        self.shard
            .shard_coordinator
            .initialize_genesis(genesis, genesis_bytes)
    }

    /// Seed the answer count at a chain's genesis. See
    /// [`hyperscale_shard::ShardCoordinator::seed_standing_answers`].
    pub(crate) fn seed_standing_answers(&mut self, height: BlockHeight, count: StandingAnswers) {
        self.shard
            .shard_coordinator
            .seed_standing_answers(height, count);
    }

    /// Hold `schedule`, folded at `epoch`, if it is newer than the one
    /// held. The replica latches its dissolution against the schedule it
    /// gives up and then against the new one, so a reading either showed
    /// survives the eviction of the windows it rested on, and drops the
    /// pending blocks it judged under a committee the new one replaces
    /// (see [`ShardCoordinator::on_schedule_replaced`]).
    fn install_schedule(&mut self, epoch: Epoch, schedule: Arc<TopologySchedule>) -> Vec<Action> {
        if epoch <= self.schedule_epoch {
            return Vec::new();
        }
        let actions = self
            .shard
            .shard_coordinator
            .on_schedule_replaced(&self.schedule, &schedule);
        self.schedule = schedule;
        self.schedule_epoch = epoch;
        actions
    }

    /// Attach `validator` to this replica at `now`, and return what it owes
    /// at once.
    ///
    /// `schedule`, folded at `epoch`, is installed first where it is newer
    /// than the one held. `record` is the signer's durable record and
    /// `persisted_qc_round` the round of the QC the store holds for its
    /// committed tip, both read from the replica's live store in the same
    /// step (see [`ShardCoordinator::attach_signer`]). On a replica already
    /// open, the signer then votes each pending block it may, proposes the
    /// round it leads, and signs each tick vote the replica holds for a
    /// committee that seats it; one not yet open owes these from its
    /// genesis or restore. The post-dispatch drain runs as after any
    /// event, so a proposal the attach queued is taken here.
    pub(crate) fn attach_signer(
        &mut self,
        now: LocalTimestamp,
        validator: ValidatorId,
        record: Option<SafeVoteRegisters>,
        persisted_qc_round: Round,
        schedule: Arc<TopologySchedule>,
        epoch: Epoch,
    ) -> Vec<Action> {
        self.shard.set_time(now);
        let mut actions = self.install_schedule(epoch, schedule);
        actions.extend(self.shard.shard_coordinator.attach_signer(
            &self.schedule,
            validator,
            record,
            persisted_qc_round,
        ));
        actions.extend(
            self.shard
                .execution_coordinator
                .attach_signer(&self.schedule, validator),
        );
        self.drain_dispatch(&mut actions);
        actions
    }

    /// Detach `validator`: the replica signs nothing further for it and
    /// keeps following the chain.
    pub(crate) fn detach_signer(&mut self, validator: ValidatorId) {
        self.shard.shard_coordinator.detach_signer(validator);
        self.shard.execution_coordinator.detach_signer(validator);
    }

    /// What every dispatch ends with: the state-root verifications that
    /// became ready, one proposal attempt if any emitter latched it, and a
    /// re-drive of the votes the fence deferred if its evidence advanced.
    fn drain_dispatch(&mut self, actions: &mut Vec<Action>) {
        let s = &mut self.shard;
        let topology_schedule = &self.schedule;
        actions.extend(
            s.shard_coordinator
                .drain_ready_state_root_verifications()
                .into_iter()
                .map(|check| Action::VerifyStateRoot(Box::new(check))),
        );

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
}

impl StateMachine for NodeStateMachine {
    #[instrument(skip(self), fields(
        shard = self.shard.local_shard.inner(),
        event = %event.type_name(),
        height = self.shard.shard_coordinator.committed_height().inner(),
    ))]
    #[allow(clippy::too_many_lines)] // single dispatch, one arm per ProtocolEvent variant
    fn handle(&mut self, now: LocalTimestamp, event: ProtocolEvent) -> Vec<Action> {
        self.shard.set_time(now);

        let sched = &self.schedule;
        let mut inputs = Vec::new();
        let mut actions = match event {
            // ── Timers ───────────────────────────────────────────────────
            ProtocolEvent::CleanupTimer => self.shard.on_cleanup_timer(sched),
            ProtocolEvent::ViewChangeTimer => self.shard.on_view_change_timer(sched),
            ProtocolEvent::ProposalPaceTimer => self.shard.try_event_driven_proposal(sched),
            ProtocolEvent::ProposalFetchTimer => {
                self.shard.shard_coordinator.fetch_overdue_proposals()
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

            // ── Shard consensus ──────────────────────────────────────────
            ProtocolEvent::BlockHeaderReceived { header, manifest } => self
                .shard
                .on_block_header_received(sched, &header, manifest),
            ProtocolEvent::QuorumCertificateFormed { block_hash, qc } => {
                self.shard.on_qc_formed(sched, block_hash, &qc)
            }
            // Structural pre-checks happen in the remote header
            // coordinator; downstream consumers receive headers via
            // `RemoteHeaderAdmitted`.
            ProtocolEvent::UnverifiedRemoteHeaderReceived {
                certified_header,
                sender,
            } => self
                .shard
                .remote_headers_coordinator
                .on_remote_header_received(sched, certified_header, sender),
            ProtocolEvent::VerifiedRemoteHeaderReceived {
                certified_header,
                sender,
            } => self
                .shard
                .remote_headers_coordinator
                .on_verified_remote_header_received(sched, certified_header, sender),
            ProtocolEvent::RemoteHeadersBelowFloor {
                source_shard,
                floor,
            } => {
                self.shard.remote_headers_coordinator.on_source_below_floor(
                    sched,
                    source_shard,
                    floor,
                );
                Vec::new()
            }
            ProtocolEvent::RemoteHeaderQcVerified {
                certified_header,
                sender,
                result,
            } => self
                .shard
                .remote_headers_coordinator
                .on_remote_header_qc_verified(sched, &certified_header, sender, *result),
            ProtocolEvent::CommitProofNeeded {
                source_shard,
                block_height,
            } => self.shard.remote_headers_coordinator.request_commit_proof(
                sched,
                source_shard,
                block_height,
            ),
            ProtocolEvent::VerifiedBlockVoteReceived { vote } => self
                .shard
                .shard_coordinator
                .on_verified_block_vote(sched, vote),
            ProtocolEvent::UnverifiedBlockVoteReceived { vote } => self
                .shard
                .shard_coordinator
                .on_unverified_block_vote(sched, vote),
            ProtocolEvent::VerifiedTimeoutReceived { timeout } => self
                .shard
                .shard_coordinator
                .on_verified_timeout(sched, timeout),
            ProtocolEvent::UnverifiedTimeoutReceived { timeout } => self
                .shard
                .shard_coordinator
                .on_unverified_timeout(sched, &timeout),
            ProtocolEvent::QcAnnouncementReceived { announcement } => self
                .shard
                .shard_coordinator
                .on_qc_announcement(sched, &announcement),
            ProtocolEvent::ReadySignalReceived { signal } => {
                self.shard
                    .shard_coordinator
                    .on_ready_signal_received(sched, signal);
                Vec::new()
            }
            ProtocolEvent::BlockReadyToCommit { certified, source } => self
                .shard
                .shard_coordinator
                .on_block_ready_to_commit(sched, certified, source),
            ProtocolEvent::QuorumCertificateResult {
                block_hash,
                qc,
                verified_votes,
                binding,
            } => self
                .shard
                .shard_coordinator
                .on_qc_result(block_hash, binding, qc, verified_votes),
            ProtocolEvent::QcSignatureVerified { subject, result } => self
                .shard
                .shard_coordinator
                .on_qc_signature_verified(sched, subject, result),
            ProtocolEvent::BlockCheckCompleted {
                block_hash,
                kind,
                outcome,
            } => self
                .shard
                .shard_coordinator
                .on_block_check_completed(sched, block_hash, kind, outcome),
            ProtocolEvent::ProposalBuilt {
                height,
                round,
                block,
                block_hash,
                finalizations,
                provisions,
                bytes_delta,
                answers,
                additions,
            } => self.shard.shard_coordinator.on_proposal_built(
                sched,
                height,
                round,
                &block,
                block_hash,
                finalizations,
                provisions,
                bytes_delta,
                answers,
                additions,
            ),
            ProtocolEvent::BlockPersisted {
                height,
                substate_bytes,
                standing_answers,
            } => self
                .shard
                .on_block_persisted(sched, height, substate_bytes, standing_answers),
            ProtocolEvent::FinalizationsAdmitted { finalizations } => {
                self.shard.on_finalizations_admitted(sched, &finalizations)
            }

            // A fork is proven — locally assembled from verified headers, or
            // a peer's proof that just verified. The shard layer engages its
            // local provisional fence and re-gossips, and the proof goes into
            // the beacon observation buffer, so the next beacon proposal
            // funnels it into a fork-caused recovery.
            ProtocolEvent::ShardForkDetected { proof } => {
                inputs.push(BeaconInput::ForkProof(proof.clone()));
                self.shard.on_fork_proven(sched, *proof)
            }
            ProtocolEvent::ShardForkProofVerified { proof, verified } => {
                if verified {
                    inputs.push(BeaconInput::ForkProof(proof.clone()));
                }
                self.shard.on_fork_proof_verified(sched, *proof, verified)
            }
            // A gossiped proof: resolve committees from the local schedule
            // and dispatch off-thread verification (self-authenticating, no
            // sender trust).
            ProtocolEvent::UnverifiedShardForkProofReceived { proof } => {
                self.shard.on_unverified_fork_proof(sched, *proof)
            }

            // A double-vote pair the local vote keeper caught goes to the
            // beacon, whose next proposal carries it to conviction.
            ProtocolEvent::ShardVoteEquivocationDetected { evidence } => {
                inputs.push(BeaconInput::VoteEquivocation { evidence });
                Vec::new()
            }

            // ── Provisions ───────────────────────────────────────────────
            ProtocolEvent::UnverifiedProvisionsReceived { provisions } => self
                .shard
                .provisions_coordinator
                .on_state_provisions_received(sched, Arc::unwrap_or_clone(provisions)),
            ProtocolEvent::VerifiedProvisionsReceived { provisions } => {
                let now = self.shard.now;
                self.shard
                    .provisions_coordinator
                    .on_verified_state_provisions_received(sched, provisions, now)
            }
            ProtocolEvent::StateProvisionsVerified { result, anchor } => {
                let now = self.shard.now;
                self.shard
                    .provisions_coordinator
                    .on_state_provisions_verified(result, anchor, now)
            }
            ProtocolEvent::CrossingReadingsReceived { claims } => {
                self.shard.on_crossing_readings(sched, claims)
            }
            ProtocolEvent::ProvisionsAdmitted { provisions, .. } => {
                self.shard.on_provisions_admitted(sched, provisions)
            }
            ProtocolEvent::OutboundProvisionBroadcast {
                provisions,
                target_shard,
            } => {
                self.shard
                    .outbound_provisions
                    .on_broadcast(&provisions, target_shard);
                Vec::new()
            }

            // ── Execution ────────────────────────────────────────────────
            ProtocolEvent::ExecutionBatchCompleted { tick, outcome } => self
                .shard
                .on_execution_batch_completed(sched, tick, outcome),
            ProtocolEvent::ExecutionBatchUnavailable {
                tick,
                tick_ts,
                env,
                requests,
                included,
                package,
            } => self
                .shard
                .execution_coordinator
                .on_execution_batch_unavailable(tick, tick_ts, env, requests, included, package),
            ProtocolEvent::ExecutionVoteReceived { vote } => self
                .shard
                .execution_coordinator
                .on_execution_vote(sched, vote),
            ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                tick_id,
                block_hash,
                verified_votes,
            } => self.shard.execution_coordinator.on_votes_verified(
                sched,
                tick_id,
                block_hash,
                verified_votes,
            ),
            ProtocolEvent::ExecutionCertificateAggregated {
                tick_id,
                certificate,
            } => self.shard.execution_coordinator.on_certificate_aggregated(
                sched,
                &tick_id,
                &certificate,
            ),
            ProtocolEvent::ExecutionCertificatesReceived { certificates } => self
                .shard
                .on_execution_certificates_received(sched, certificates),
            ProtocolEvent::ExecutionCertificateSignatureVerified { result } => self
                .shard
                .execution_coordinator
                .on_certificate_verified(sched, result),
            ProtocolEvent::ExecutionCertificateAdmitted { certificate } => self
                .shard
                .on_execution_certificate_admitted(sched, &certificate),
            ProtocolEvent::FinalizationsReceived { finalizations } => {
                self.shard.on_finalizations_received(sched, finalizations)
            }
            ProtocolEvent::FinalizationVerified { result } => self
                .shard
                .execution_coordinator
                .on_finalization_verified(result),
            ProtocolEvent::LegsHalfBuilt { tick, tip, half } => self
                .shard
                .execution_coordinator
                .on_legs_half_built(tick, tip, half),

            // ── Transactions ─────────────────────────────────────────────
            ProtocolEvent::TransactionValidated {
                tx,
                submitted_locally,
            } => self
                .shard
                .on_transaction_validated(sched, tx, submitted_locally),
            ProtocolEvent::TransactionsReceived { transactions } => {
                self.shard.on_transactions_fetched(sched, transactions)
            }
            ProtocolEvent::TransactionsAdmitted { txs } => {
                self.shard.on_transactions_admitted(sched, &txs)
            }
            ProtocolEvent::TransactionsResolved { resolutions } => {
                self.shard.mempool_coordinator.on_resolutions(&resolutions)
            }

            // ── Sync ─────────────────────────────────────────────────────
            ProtocolEvent::BlockSyncReadyToApply { certified } => {
                self.shard.on_block_sync_ready_to_apply(sched, certified)
            }
            ProtocolEvent::BlockSyncComplete { .. } => self.shard.on_block_sync_complete(sched),
            ProtocolEvent::CommittedStateRestored { height, hash, qc } => self
                .shard
                .on_committed_state_restored(sched, height, hash, qc),
            ProtocolEvent::SettledTxsReconstructed {
                shard,
                txs,
                terminal_wt,
            } => self.shard.on_settled_txs_reconstructed(
                sched,
                shard,
                SettledTxSet { txs, terminal_wt },
            ),
            ProtocolEvent::FetchedStateProofVerified {
                anchor,
                keys,
                proof,
                values,
            } => {
                self.shard
                    .on_fetched_state_proof_verified(anchor, &keys, &proof, &values);
                Vec::new()
            }
            ProtocolEvent::FetchedVerdictProofVerified {
                anchor,
                questions,
                proof,
            } => {
                self.shard
                    .on_fetched_verdict_proof_verified(sched, anchor, &questions, &proof);
                Vec::new()
            }

            // ── Beacon ───────────────────────────────────────────────────
            // A schedule the beacon folded: held if newer, then the shard
            // coordinators replay what waited on the epoch.
            ProtocolEvent::BeaconBlockPersisted { epoch, schedule } => {
                let mut actions = self.install_schedule(epoch, schedule);
                actions.extend(self.shard.on_beacon_block_persisted(&self.schedule));
                actions
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

        self.drain_dispatch(&mut actions);

        actions
    }
}
