//! Per-host driver for the beacon: the beacon loop.
//!
//! A [`BeaconLoop`] runs on every host. It owns the host's one
//! [`BeaconFold`], which follows the beacon chain for every shard chain
//! the host runs, and one [`BeaconParticipant`] per validator identity the
//! host holds, each running that identity's SPC, ratification and
//! proposal duty against the fold. It also owns the host's beacon-block
//! catch-up sync and the beacon fetches its fold and participants ask for.
//!
//! The loop is the one writer of the host's beacon commits and of the
//! topology the process publishes. After each adoption it hands every
//! registered chain's loop the schedule it folded, as
//! [`ProtocolEvent::BeaconBlockPersisted`]. A chain's loop reports what
//! its replica commits, certifies and admits back through
//! [`BeaconScopedInput::Shard`].
//!
//! Beacon-owned delegated actions run on the consensus dispatch pool:
//! a participant's through the same
//! [`hyperscale_beacon::action_handlers`] over the storage-free
//! `BeaconActionContext`, the fold's block checks through
//! [`verify_beacon_block`]. Each outcome returns to its owner as a
//! [`BeaconScopedInput::Continuation`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_beacon::action_handlers::{
    handle_action as handle_beacon_action, verify_beacon_block,
};
use hyperscale_beacon::coordinator::{LocalChainAnchors, retention_floor};
use hyperscale_beacon::verification::RatifyVoteSlotKey;
use hyperscale_beacon::{
    Adopted, BeaconFold, BeaconParticipant, CandidateKeys, ChainRegistration, ParticipantStep,
};
use hyperscale_core::{
    Action, ActionOwner, BeaconActionContext, BeaconFetchIds, FetchIds, FetchRequest, Gate,
    ParticipationChange, ProtocolEvent,
};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_network::{Answerers, Network, RequestError, ResponseVerdict};
use hyperscale_storage::{BeaconStorage, ShardStorage};
use hyperscale_types::network::gossip::ShardVoteEquivocationGossip;
use hyperscale_types::network::request::beacon::GetBeaconBlockRequest;
use hyperscale_types::network::response::beacon::GetBeaconBlockResponse;
use hyperscale_types::{
    Address, BeaconBlockHash, BeaconProposal, BeaconState, BlockHash, BlockHeight,
    CandidateBeaconBlock, CandidateVerifyContext, CertifiedBeaconBlock, CertifiedBlockHeader,
    Epoch, GenesisConfigHash, Hash, LeafIndex, LocalTimestamp, MessageClass, NetworkDefinition,
    ShardId, ShardVoteEquivocation, Signer, SlotEffects, TopologySchedule, TopologySnapshot,
    ValidatorId, ValidatorStatus, Verifiable, Verified, Verifier, verify_shard_vote_equivocation,
};
use tracing::warn;

use crate::beacon::{
    self, BeaconBlockSync, BeaconBlockSyncInput, BeaconBlockSyncOutput, BeaconCandidateBinding,
    BeaconFetchState, BeaconProposalBinding, BeaconReply, ProposalKeys, ShardWitnessBinding,
};
use crate::config::NodeConfig;
use crate::event::{
    Attachment, BeaconInput, BeaconOwner, BeaconScopedInput, FetchFailureKind, HostEvent,
    Registration, classify_fetch_error,
};
use crate::fetch::{FetchInput, FetchOutput, FetchedBy, Release};
use crate::process::ProcessIo;
use crate::shard::mempool::DeferredForRecords;
use crate::shard::{FetchTicker, StepOutput, TimerOp, TimerOwner};
use crate::sync::SyncOutput;

mod records;
mod submissions;

pub(crate) use records::custodian;
use records::{InstanceRecordBinding, PackageArtifactBinding};

/// The host's beacon driver.
pub struct BeaconLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    /// Process-scoped resources shared with every other driver on the host:
    /// beacon storage, the topology `ArcSwap`, the dispatch pool.
    process: Arc<ProcessIo<S, N, D>>,

    /// The host's one fold of the beacon chain.
    fold: BeaconFold,

    /// One participant per validator identity the host holds.
    participants: BTreeMap<ValidatorId, Participant>,

    /// Each registered chain's shard and its loop's channel.
    shard_senders: BTreeMap<ChainRegistration, (ShardId, Sender<HostEvent>)>,

    /// Which registered chain's loop each outstanding commit-proof ask
    /// went to, so a loop that closes hands its asks to another.
    proof_routes: BTreeMap<(ShardId, BlockHeight), ChainRegistration>,

    /// Cached wall-clock time, set by [`NodeHost::set_time`](crate::host::NodeHost::set_time).
    now: LocalTimestamp,

    /// Per-step scratch: placement deltas emitted via
    /// `Action::ReconfigureParticipation` — the seat/drain triggers the runner
    /// acts on. Cleared at step entry, drained into the step's `StepOutput`.
    pending_participation_changes: Vec<ParticipationChange>,

    /// Per-step scratch: every certified header a chain loop reported this
    /// step, its own or a remote shard's, for a host that summarises them
    /// ([`Self::take_admitted`]). Cleared at step entry, so a host that never
    /// drains it holds one step's worth at most.
    pending_admitted: Vec<Arc<Verified<CertifiedBlockHeader>>>,

    /// Per-step scratch: each epoch adopted this step with what its fold
    /// settled, in the order the epochs folded ([`Self::take_adopted`]).
    /// Cleared at step entry like [`Self::pending_admitted`].
    pending_adopted: Vec<(Epoch, SlotEffects)>,

    /// Per-step scratch: timer operations, each owned by the participant
    /// that armed it or by the loop for its fetch tick.
    pending_timer_ops: Vec<TimerOp>,

    /// Per-step scratch: count of actions the fold and participants
    /// produced.
    actions_generated: usize,

    /// Beacon-block catch-up sync, scope `()`. The fold emits
    /// `Action::StartBeaconBlockSync` when a gossiped block sits more than
    /// one epoch ahead of its tip; this FSM drives the
    /// `GetBeaconBlockRequest` fetches that close the gap.
    beacon_block: BeaconBlockSync,

    /// Where the next catch-up ask lands among the live leaves. Seeded
    /// by the moment the loop started, so hosts started apart begin
    /// apart, and advanced by every ask, so a retry goes to another
    /// leaf's committee.
    sync_spread: u64,

    /// The witness, proposal and candidate fetches the fold and the
    /// participants ask for.
    fetches: BeaconFetchState,

    /// Which owners want each fetched id.
    interest: Interest,

    /// Where the fetches' answers return: the host's beacon channel.
    reply: BeaconReply,

    /// The one fetch tick that retries both the fetches and the sync, and
    /// sweeps the held submissions.
    fetch_tick: FetchTicker,

    /// The host's own submissions waiting on the records they name.
    submissions: DeferredForRecords,

    /// Each peer item check in flight, with every participant waiting on
    /// its outcome. Co-hosted participants are handed the same gossiped
    /// vote or candidate, and the check against the shared fold comes out
    /// the same for each, so the first to ask runs it and the outcome is
    /// handed to all.
    shared_checks: BTreeMap<SharedCheck, BTreeSet<Attachment>>,

    /// Packages an off-thread install is reading from the stores this
    /// host serves, so a repeat want waits on that install rather than
    /// starting another.
    installing: BTreeSet<Hash>,
}

/// One identity's beacon participation on the loop.
struct Participant {
    attachment: Attachment,
    duty: BeaconParticipant,
    signer: Arc<dyn Signer>,
    /// The release gate every signature the participant dispatches
    /// enters, closed when the participant is removed.
    gate: Arc<Gate>,
}

impl<S, N, D> BeaconLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Build the host's beacon loop around `fold`, with no chain
    /// registered and no participant.
    pub(crate) fn new(
        process: Arc<ProcessIo<S, N, D>>,
        fold: BeaconFold,
        config: &NodeConfig,
    ) -> Self {
        let now = fold.now();
        let beacon_block = beacon::resumed_at(fold.latest_block().epoch());
        Self {
            reply: BeaconReply::new(
                process.beacon_event_sender.clone(),
                ProposalKeys {
                    topology: process.topology_snapshot.clone(),
                    verifier: Arc::clone(&process.verifier),
                    network: fold.network().clone(),
                },
            ),
            process,
            fold,
            participants: BTreeMap::new(),
            shard_senders: BTreeMap::new(),
            proof_routes: BTreeMap::new(),
            now,
            pending_participation_changes: Vec::new(),
            pending_admitted: Vec::new(),
            pending_adopted: Vec::new(),
            pending_timer_ops: Vec::new(),
            actions_generated: 0,
            beacon_block,
            sync_spread: now.as_millis(),
            fetches: BeaconFetchState::new(config),
            interest: Interest::default(),
            fetch_tick: FetchTicker::default(),
            submissions: DeferredForRecords::new(),
            shared_checks: BTreeMap::new(),
            installing: BTreeSet::new(),
        }
    }

    /// Track a chain a loop is about to run from its recovered committed
    /// `height` and the anchors its tip carries, and send the chain's
    /// beacon events to `sender` from now on.
    ///
    /// A chain anchored below the oldest window the fold retains widens
    /// the schedule from beacon storage first, so the replica built from
    /// the returned schedule resolves its tip's committee.
    pub(crate) fn register(
        &mut self,
        shard: ShardId,
        anchors: LocalChainAnchors,
        height: BlockHeight,
        sender: Sender<HostEvent>,
    ) -> Registration {
        let anchor_epoch = self
            .fold
            .state()
            .chain_config
            .epoch_windows()
            .epoch_for(anchors.committee);
        if self
            .fold
            .schedule()
            .retained_epochs()
            .is_some_and(|(oldest, _)| anchor_epoch < oldest)
        {
            let floor = retention_floor(self.fold.state(), Some(anchors.committee), self.now);
            let history = self.process.beacon_storage.states_since(floor);
            self.fold.widen(&history);
        }
        let token = self.fold.register_chain(shard, anchors, height);
        self.shard_senders.insert(token, (shard, sender));
        Registration {
            token,
            schedule: Arc::clone(self.fold.shared_schedule()),
            epoch: self.fold.state().current_epoch,
            chain_config: self.fold.state().chain_config,
        }
    }

    /// Stop tracking the chain `token` names. The commit-proof asks its
    /// loop held go to another registered loop, and what it asked for on
    /// its own behalf is wanted by it no longer.
    pub(crate) fn deregister(&mut self, token: ChainRegistration) {
        self.fold.deregister_chain(token);
        self.shard_senders.remove(&token);
        self.forget::<InstanceRecordBinding>(BeaconOwner::Chain(token));
        self.forget::<PackageArtifactBinding>(BeaconOwner::Chain(token));
        let held: Vec<(ShardId, BlockHeight)> = self
            .proof_routes
            .iter()
            .filter(|(_, route)| **route == token)
            .map(|(ask, _)| *ask)
            .collect();
        for ask in held {
            self.proof_routes.remove(&ask);
            self.route_proof_ask(ask);
        }
    }

    /// Run `validator`'s beacon participation on this host from now on,
    /// resumed from its durable ratification record. Its startup timers,
    /// and the join its committed lookahead already owes it, land in the
    /// scratch for the caller to drain. No-op if the loop already runs it.
    pub(crate) fn add_participant(&mut self, validator: ValidatorId, signer: Arc<dyn Signer>) {
        if self.participants.contains_key(&validator) {
            return;
        }
        let mut participant = BeaconParticipant::new(&self.fold, validator);
        if let Some(record) = self.process.beacon_storage.ratify_record(validator) {
            participant.install_recovered_ratify_record(&self.fold, &record);
        }
        self.participants.insert(
            validator,
            Participant {
                attachment: self.process.attach(validator),
                duty: participant,
                signer,
                gate: Arc::new(Gate::new()),
            },
        );
        self.arm_startup(validator);
        self.refresh_committee_flag();
    }

    /// Stop running `validator`'s participation. Its release gate closes
    /// before this returns, so none of its signatures leaves the host
    /// afterwards, and the fetches only it asked for are released. What
    /// it left in flight, continuations and timers alike, is dropped on
    /// arrival. Returns whether the loop ran it.
    pub(crate) fn remove_participant(&mut self, validator: ValidatorId) -> bool {
        let Some(participant) = self.participants.remove(&validator) else {
            return false;
        };
        participant.gate.close_and_wait();
        let owner = BeaconOwner::Participant(participant.attachment);
        self.forget::<BeaconProposalBinding>(owner);
        self.forget::<BeaconCandidateBinding>(owner);
        self.refresh_committee_flag();
        true
    }

    /// The identities the loop runs a participant for.
    pub(crate) fn validators(&self) -> impl Iterator<Item = ValidatorId> + '_ {
        self.participants.keys().copied()
    }

    /// [`Self::validators`], held apart from the loop so a walk over them
    /// can drive each.
    fn validator_list(&self) -> Vec<ValidatorId> {
        self.validators().collect()
    }

    /// The host's fold.
    #[must_use]
    pub(crate) const fn fold(&self) -> &BeaconFold {
        &self.fold
    }

    /// `validator`'s participant, if the loop runs one.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn participant(&self, validator: ValidatorId) -> Option<&BeaconParticipant> {
        self.participants.get(&validator).map(|p| &p.duty)
    }

    /// Re-arm every participant's beacon startup timers and drain the
    /// result — the production beacon thread's spawn-time bootstrap.
    /// Re-arming is idempotent: it replaces the pending fire at the runner's
    /// table with one at the same deadline.
    pub fn startup_output(&mut self) -> StepOutput {
        self.clear_scratch();
        for validator in self.validator_list() {
            self.arm_startup(validator);
        }
        self.take_output()
    }

    /// Arm `validator`'s committee-start and ratify timers off the
    /// fold's clock.
    fn arm_startup(&mut self, validator: ValidatorId) {
        let actions = self.fold.on_startup();
        self.run_participant_actions(validator, actions);
    }

    /// Set the cached wall-clock time every handler in the next step
    /// reads.
    pub const fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
        self.fold.set_now(now);
    }

    /// Clear per-step scratch. Called by [`NodeHost::step`](crate::host::NodeHost::step)
    /// before dispatch so the drained output reflects only this step.
    pub(crate) fn clear_scratch(&mut self) {
        self.pending_participation_changes.clear();
        self.pending_admitted.clear();
        self.pending_adopted.clear();
        self.pending_timer_ops.clear();
        self.actions_generated = 0;
    }

    /// Drive one beacon input and return the step's output: the placement
    /// deltas the participants surfaced and the timer operations. Clears
    /// per-step scratch first, mirroring
    /// [`ShardLoop::run_step`](crate::shard::ShardLoop::run_step); used by
    /// the production beacon thread, which owns the `BeaconLoop` directly
    /// rather than driving it through
    /// [`NodeHost::step`](crate::host::NodeHost::step).
    pub fn run_step(&mut self, input: BeaconScopedInput) -> StepOutput {
        self.clear_scratch();
        self.dispatch_event(input);
        self.take_output()
    }

    /// The certified headers reported since the last step began, oldest
    /// first, emptying the scratch. The production beacon thread drains it
    /// after each step to keep its header summaries.
    pub fn take_admitted(&mut self) -> Vec<Arc<Verified<CertifiedBlockHeader>>> {
        std::mem::take(&mut self.pending_admitted)
    }

    /// The epochs adopted since the last step began, each with what its fold
    /// settled, oldest first, emptying the scratch.
    pub fn take_adopted(&mut self) -> Vec<(Epoch, SlotEffects)> {
        std::mem::take(&mut self.pending_adopted)
    }

    /// The fold's latest committed beacon state.
    #[must_use]
    pub const fn beacon_state(&self) -> &BeaconState {
        self.fold.state()
    }

    /// The topology schedule the fold keeps: every retained epoch's
    /// committees, by which a reported header's signers resolve.
    #[must_use]
    pub fn schedule(&self) -> &TopologySchedule {
        self.fold.schedule()
    }

    /// Drain this step's scratch into a [`StepOutput`]. The loop emits no
    /// transaction statuses, so that field stays empty.
    pub(crate) fn take_output(&mut self) -> StepOutput {
        StepOutput {
            actions_generated: std::mem::replace(&mut self.actions_generated, 0),
            timer_ops: std::mem::take(&mut self.pending_timer_ops),
            participation_changes: std::mem::take(&mut self.pending_participation_changes),
            ..StepOutput::default()
        }
    }

    /// Route a [`BeaconScopedInput`] to the fold, the participants, the
    /// fetches or the catch-up sync, then keep the fetch tick armed
    /// exactly while either has work pending.
    pub(crate) fn dispatch_event(&mut self, input: BeaconScopedInput) {
        match input {
            BeaconScopedInput::Protocol(event) => self.on_protocol(*event),
            BeaconScopedInput::Continuation {
                owner: BeaconOwner::Fold,
                event,
            } => self.on_fold_outcome(*event),
            BeaconScopedInput::Continuation {
                owner: BeaconOwner::Participant(_),
                event,
            } if SharedCheck::of_outcome(&event).is_some() => self.on_shared_check(*event),
            BeaconScopedInput::Continuation {
                owner: BeaconOwner::Participant(attachment),
                event,
            }
            | BeaconScopedInput::ParticipantTimer {
                participant: attachment,
                event,
            } => {
                if self
                    .participants
                    .get(&attachment.validator)
                    .is_some_and(|p| p.attachment == attachment)
                {
                    self.on_participant_event(attachment.validator, *event);
                }
            }
            BeaconScopedInput::Continuation {
                owner: BeaconOwner::Chain(_) | BeaconOwner::Submissions,
                event,
            } => warn!(
                event = event.type_name(),
                "BeaconLoop: only the fold and participants dispatch beacon actions — dropping"
            ),
            BeaconScopedInput::BeaconBlockSyncResponseReceived { epoch, block } => {
                self.on_sync_response(epoch, block);
            }
            BeaconScopedInput::BeaconBlockSyncFetchFailed { epoch, kind } => {
                self.on_sync_fetch_failed(epoch, kind);
            }
            BeaconScopedInput::FetchFailed(ids) => self.release(ids, Release::Failed),
            BeaconScopedInput::FetchUnroutable(ids) => self.release(ids, Release::Unroutable),
            BeaconScopedInput::FetchFulfilled(ids) => self.release(ids, Release::Admitted),
            BeaconScopedInput::Answered { ids, event } => self.on_answer(ids, *event),
            BeaconScopedInput::FetchTick => {
                self.fetch_tick.fired();
                self.drive_fetch::<ShardWitnessBinding>(FetchInput::Tick);
                self.drive_fetch::<BeaconProposalBinding>(FetchInput::Tick);
                self.drive_fetch::<BeaconCandidateBinding>(FetchInput::Tick);
                self.drive_fetch::<InstanceRecordBinding>(FetchInput::Tick);
                self.drive_fetch::<PackageArtifactBinding>(FetchInput::Tick);
                self.on_sync_tick();
                self.sweep_submissions();
            }
            BeaconScopedInput::SubmissionWantsRecords { deferred } => {
                self.hold_submission(deferred);
            }
            BeaconScopedInput::InstanceRecordsFetched { records } => {
                self.on_instance_records_fetched(records);
            }
            BeaconScopedInput::PackageArtifactsFetched { artifacts } => {
                self.on_package_artifacts_fetched(artifacts);
            }
            BeaconScopedInput::PackagesInstalled { packages, unheld } => {
                self.on_packages_installed(packages, unheld);
            }
            BeaconScopedInput::Shard { chain, input } => self.on_shard_input(chain, input),
            BeaconScopedInput::Register {
                shard,
                anchors,
                height,
                sender,
                reply,
            } => {
                let registration = self.register(shard, anchors, height, sender);
                (reply.0)(registration);
            }
            BeaconScopedInput::Deregister(token) => self.deregister(token),
            BeaconScopedInput::AddParticipant { validator, signer } => {
                self.add_participant(validator, signer);
            }
        }
        self.update_fetch_tick_timer();
    }

    /// A beacon event off the wire or a fetch: block reception and
    /// witness chunks go to the fold once, the rest to every participant,
    /// each of which filters on its own membership.
    fn on_protocol(&mut self, event: ProtocolEvent) {
        match event {
            ProtocolEvent::BeaconBlockReceived { block }
            | ProtocolEvent::BeaconBlockSyncReadyToApply { block } => {
                let actions = self.fold.on_beacon_block_received(block);
                self.run_fold_actions(actions);
            }
            ProtocolEvent::UnverifiedShardVoteEquivocationReceived { evidence } => {
                self.verify_vote_equivocation(evidence);
            }
            ProtocolEvent::BeaconProposalReceived {
                from,
                epoch,
                proposal,
            } => {
                if let Some(proposal) = Self::sealed(from, proposal) {
                    for validator in self.validator_list() {
                        let proposal = Arc::clone(&proposal);
                        self.drive(validator, |p, fold| {
                            p.on_beacon_proposal_received(fold, from, epoch, proposal)
                        });
                    }
                }
            }
            other => {
                for validator in self.validator_list() {
                    self.on_participant_event(validator, other.clone());
                }
            }
        }
    }

    /// A fetch's answer. Its ids retire only once what it carries has
    /// passed the check its consumers would run, and before what it
    /// carries is taken, so the freed capacity is there for any fetch
    /// that re-drives. An answer that fails its check releases its ids
    /// as failed instead, which retries them at once the first time and
    /// on the tick after: an await the answer was to resolve stays open
    /// for another peer's.
    fn on_answer(&mut self, ids: FetchIds, event: ProtocolEvent) {
        match event {
            ProtocolEvent::ShardWitnessesReceived {
                shard_id,
                committed_block_hash,
                lo,
                payloads,
                range_proof,
            } => match self.fold.on_shard_witnesses_received(
                shard_id,
                committed_block_hash,
                lo,
                payloads,
                range_proof,
            ) {
                Some(actions) => {
                    self.release(ids, Release::Admitted);
                    self.run_fold_actions(actions);
                }
                None => self.release(ids, Release::Failed),
            },
            ProtocolEvent::BeaconProposalFetched {
                epoch,
                validator: author,
                proposal,
            } => match Self::sealed(author, proposal) {
                Some(proposal) => {
                    self.release(ids, Release::Admitted);
                    for validator in self.validator_list() {
                        let proposal = Arc::clone(&proposal);
                        self.drive(validator, |p, fold| {
                            p.on_beacon_proposal_fetched(fold, epoch, author, proposal)
                        });
                    }
                }
                None => self.release(ids, Release::Failed),
            },
            ProtocolEvent::BeaconCandidateReceived { candidate } => {
                self.verify_fetched_candidate(ids, candidate);
            }
            ProtocolEvent::BeaconCandidateVerified {
                result: Ok(candidate),
                ..
            } => {
                self.release(ids, Release::Admitted);
                for validator in self.validator_list() {
                    let candidate = Arc::clone(&candidate);
                    self.drive(validator, |p, fold| {
                        p.on_beacon_candidate_fetched(fold, candidate)
                    });
                }
            }
            other => {
                warn!(
                    event = other.type_name(),
                    "BeaconLoop: an answer no beacon fetch gives — dropping"
                );
                self.release(ids, Release::Failed);
            }
        }
    }

    /// Check a fetched candidate once for every participant, off-thread,
    /// against the fold's tip. A verified one returns to
    /// [`Self::on_answer`] and is kept for serving; one that fails
    /// releases its ids for another peer's answer.
    fn verify_fetched_candidate(
        &mut self,
        ids: FetchIds,
        candidate: Arc<Verifiable<CandidateBeaconBlock>>,
    ) {
        let Some(CandidateKeys {
            committee,
            equivocation_signers,
        }) = self.fold.candidate_keys(&candidate)
        else {
            self.release(ids, Release::Failed);
            return;
        };
        let handles = Arc::clone(&self.process.dispatch_handles);
        let verifier = Arc::clone(&self.process.verifier);
        let network = self.fold.network().clone();
        let beacon_tx = self.process.beacon_event_sender.clone();
        self.process
            .dispatch
            .spawn(DispatchPool::Consensus, move || {
                let checked = Arc::unwrap_or_clone(candidate).upgrade(&CandidateVerifyContext {
                    network: &network,
                    committee: &committee,
                    equivocation_signers: &equivocation_signers,
                    verifier: verifier.as_ref(),
                });
                let input = match checked {
                    Ok(candidate) => {
                        let candidate = Arc::new(candidate);
                        handles.beacon_candidate_cache.admit(Arc::clone(&candidate));
                        BeaconScopedInput::Answered {
                            ids,
                            event: Box::new(ProtocolEvent::BeaconCandidateVerified {
                                block_hash: candidate.block_hash(),
                                result: Ok(candidate),
                            }),
                        }
                    }
                    Err((_, err)) => {
                        warn!(%err, "fetched BeaconCandidate failed verification — asking again");
                        BeaconScopedInput::FetchFailed(ids)
                    }
                };
                let _ = beacon_tx.send(HostEvent::Beacon(input));
            });
    }

    /// The outcome of a check the fold dispatched.
    fn on_fold_outcome(&mut self, event: ProtocolEvent) {
        match event {
            ProtocolEvent::BeaconBlockVerified { result } => {
                if let Some(adopted) = self.fold.on_beacon_block_verified(result) {
                    self.settle(adopted);
                }
            }
            ProtocolEvent::ShardVoteEquivocationVerified { evidence, verified } => {
                if verified {
                    self.observe_vote_equivocation(evidence);
                } else {
                    warn!("discarding a shard double-vote pair that failed verification");
                }
            }
            other => warn!(
                event = other.type_name(),
                "BeaconLoop: unexpected fold outcome — dropping"
            ),
        }
    }

    /// Feed one participant a beacon consensus event.
    #[allow(clippy::too_many_lines)] // single dispatch over the participant's ProtocolEvent variants
    fn on_participant_event(&mut self, validator: ValidatorId, event: ProtocolEvent) {
        match event {
            ProtocolEvent::UnverifiedPcVote1Received { epoch, view, vote } => {
                self.drive(validator, |p, _| p.on_pc_vote1_received(epoch, view, vote));
            }
            ProtocolEvent::UnverifiedPcVote2Received { epoch, view, vote } => {
                self.drive(validator, |p, _| p.on_pc_vote2_received(epoch, view, vote));
            }
            ProtocolEvent::UnverifiedPcVote3Received { epoch, view, vote } => {
                self.drive(validator, |p, _| p.on_pc_vote3_received(epoch, view, vote));
            }
            ProtocolEvent::VerifiedPcVote1Received { epoch, view, vote } => {
                self.drive(validator, |p, fold| {
                    p.on_verified_pc_vote1_received(fold, epoch, view, vote)
                });
            }
            ProtocolEvent::VerifiedPcVote2Received { epoch, view, vote } => {
                self.drive(validator, |p, fold| {
                    p.on_verified_pc_vote2_received(fold, epoch, view, vote)
                });
            }
            ProtocolEvent::VerifiedPcVote3Received { epoch, view, vote } => {
                self.drive(validator, |p, fold| {
                    p.on_verified_pc_vote3_received(fold, epoch, view, vote)
                });
            }
            ProtocolEvent::SpcNewViewReceived {
                epoch,
                from,
                proposal,
            } => {
                self.drive(validator, |p, _| {
                    p.on_spc_new_view_received(epoch, from, proposal)
                });
            }
            ProtocolEvent::SpcNewCommitReceived { epoch, from, msg } => {
                self.drive(validator, |p, _| {
                    p.on_spc_new_commit_received(epoch, from, msg)
                });
            }
            ProtocolEvent::UnverifiedSpcEmptyViewReceived { epoch, msg } => {
                self.drive(validator, |p, _| {
                    p.on_unverified_spc_empty_view_received(epoch, msg)
                });
            }
            ProtocolEvent::VerifiedSpcEmptyViewReceived { epoch, msg } => {
                self.drive(validator, |p, fold| {
                    p.on_verified_spc_empty_view_received(fold, epoch, msg)
                });
            }
            ProtocolEvent::UnverifiedRatifyVoteReceived { vote } => {
                self.drive(validator, |p, fold| {
                    p.on_unverified_ratify_vote_received(fold, vote)
                });
            }
            ProtocolEvent::VerifiedRatifyVoteReceived { vote } => {
                self.drive(validator, |p, fold| {
                    p.on_verified_ratify_vote_received(fold, vote)
                });
            }
            ProtocolEvent::BeaconProposalReceived {
                from,
                epoch,
                proposal,
            } => {
                if let Some(proposal) = Self::sealed(from, proposal) {
                    self.drive(validator, |p, fold| {
                        p.on_beacon_proposal_received(fold, from, epoch, proposal)
                    });
                }
            }
            ProtocolEvent::BeaconCandidateReceived { candidate } => {
                self.drive(validator, |p, fold| {
                    p.on_beacon_candidate_received(fold, candidate)
                });
            }
            ProtocolEvent::BeaconCandidateVerified { block_hash, result } => {
                self.drive(validator, |p, fold| {
                    p.on_beacon_candidate_verified(fold, block_hash, result)
                });
            }
            ProtocolEvent::RatifyVoteVerified {
                anchor,
                epoch,
                round,
                phase,
                signer,
                result,
            } => {
                let key = (anchor, epoch, round, phase, signer);
                self.drive(validator, |p, fold| {
                    p.on_ratify_vote_verified(fold, key, result)
                });
            }
            ProtocolEvent::PcVote1Verified {
                epoch,
                view,
                signer,
                result,
            } => {
                self.drive(validator, |p, fold| {
                    p.on_pc_vote1_verified(fold, epoch, view, signer, result)
                });
            }
            ProtocolEvent::PcVote2Verified {
                epoch,
                view,
                signer,
                result,
            } => {
                self.drive(validator, |p, fold| {
                    p.on_pc_vote2_verified(fold, epoch, view, signer, result)
                });
            }
            ProtocolEvent::PcVote3Verified {
                epoch,
                view,
                signer,
                result,
            } => {
                self.drive(validator, |p, fold| {
                    p.on_pc_vote3_verified(fold, epoch, view, signer, result)
                });
            }
            ProtocolEvent::SpcNewViewVerified {
                epoch,
                from,
                view,
                result,
            } => {
                self.drive(validator, |p, fold| {
                    p.on_spc_new_view_verified(fold, epoch, from, view, result)
                });
            }
            ProtocolEvent::SpcNewCommitVerified {
                epoch,
                from,
                view,
                result,
            } => {
                self.drive(validator, |p, fold| {
                    p.on_spc_new_commit_verified(fold, epoch, from, view, result)
                });
            }
            ProtocolEvent::SpcEmptyViewVerified {
                epoch,
                from,
                view,
                result,
            } => {
                self.drive(validator, |p, fold| {
                    p.on_spc_empty_view_verified(fold, epoch, from, view, result)
                });
            }
            ProtocolEvent::BeaconCommitteeStartTimer => {
                self.drive(
                    validator,
                    BeaconParticipant::on_beacon_committee_start_timer,
                );
            }
            ProtocolEvent::BeaconRatifyTimer => {
                self.drive(validator, BeaconParticipant::on_beacon_ratify_timer);
            }
            ProtocolEvent::BeaconSpcViewTimer => {
                self.drive(validator, BeaconParticipant::on_beacon_spc_view_timer);
            }
            ProtocolEvent::BeaconSpcInputDwellTimer => {
                self.drive(validator, BeaconParticipant::on_spc_input_dwell_timer);
            }
            other => warn!(
                event = other.type_name(),
                "BeaconLoop: event no participant handles — dropping"
            ),
        }
    }

    /// Run a participant handler, adopting the block it certified.
    fn drive<T: Into<ParticipantStep>>(
        &mut self,
        validator: ValidatorId,
        handler: impl FnOnce(&mut BeaconParticipant, &BeaconFold) -> T,
    ) {
        let Some(participant) = self.participants.get_mut(&validator) else {
            return;
        };
        let step: ParticipantStep = handler(&mut participant.duty, &self.fold).into();
        self.run_participant_actions(validator, step.actions);
        if let Some(block) = step.certified
            && let Some(adopted) = self.fold.adopt(block)
        {
            self.settle(adopted);
        }
    }

    /// Follow an adoption through: the fold's commit and topology, the
    /// committee flag the fold's witness duty reads, the terminal witness
    /// re-drive, and each participant's half of the epoch it settled.
    /// A participant's commit-proof asks last one epoch, so the routes of
    /// the asks no participant still holds go with them.
    fn settle(&mut self, adopted: Adopted) {
        let Adopted {
            epoch,
            effects,
            actions,
        } = adopted;
        // Recorded before the participants run: driving them can adopt the
        // next epoch, which must record after this one.
        self.pending_adopted.push((epoch, effects.clone()));
        self.run_fold_actions(actions);
        self.refresh_committee_flag();
        let actions = self.fold.redrive_terminal_witness_fetches();
        self.run_fold_actions(actions);
        for validator in self.validator_list() {
            self.drive(validator, |p, fold| p.on_adopted(fold, &effects));
        }
        let participants = &self.participants;
        self.proof_routes.retain(|&(source, height), _| {
            participants.values().any(|p| p.duty.asked(source, height))
        });
    }

    /// Set the fold's committee flag to whether any participant sits on
    /// the beacon committee.
    fn refresh_committee_flag(&mut self) {
        let on = self
            .participants
            .values()
            .any(|p| p.duty.is_on_committee(&self.fold));
        let actions = self.fold.set_host_on_committee(on);
        self.run_fold_actions(actions);
    }

    /// What a chain's loop reported: the fold records it, and every
    /// participant re-evaluates the proposals it was waiting on. A report
    /// under a registration the loop no longer holds is a closed loop's
    /// late word, and changes nothing.
    fn on_shard_input(&mut self, chain: ChainRegistration, input: BeaconInput) {
        if !self.shard_senders.contains_key(&chain) {
            return;
        }
        match input {
            BeaconInput::LocalCommit { header } => {
                self.pending_admitted.push(Arc::clone(&header));
                let actions = self.fold.on_local_block_committed(chain, &header);
                self.run_fold_actions(actions);
                self.release_awaited_proposals();
            }
            BeaconInput::CertifiedHeader { header } => {
                self.pending_admitted.push(Arc::clone(&header));
                self.fold.on_certified_local_header(chain, &header);
                self.release_awaited_proposals();
            }
            BeaconInput::SourceHeader { header } => {
                self.pending_admitted.push(Arc::clone(&header));
                let actions = self.fold.on_source_header(&header);
                self.run_fold_actions(actions);
                self.release_awaited_proposals();
            }
            BeaconInput::CommitProven { header } => {
                self.proof_routes
                    .remove(&(header.shard_id(), header.height()));
                if self
                    .fold
                    .admit_proven_for(&header, self.participants.values().map(|p| &p.duty))
                {
                    self.release_awaited_proposals();
                }
            }
            BeaconInput::ForkProof(proof) => {
                for participant in self.participants.values_mut() {
                    participant
                        .duty
                        .observe_fork_proof(&self.fold, (*proof).clone());
                }
            }
            BeaconInput::VoteEquivocation { evidence } => {
                self.observe_vote_equivocation(evidence);
            }
            BeaconInput::RecordsWanted {
                instances,
                packages,
            } => self.want_records(BeaconOwner::Chain(chain), instances, packages),
            BeaconInput::RecordsAbandoned {
                instances,
                packages,
            } => self.abandon_records(BeaconOwner::Chain(chain), instances, packages),
        }
    }

    fn release_awaited_proposals(&mut self) {
        for validator in self.validator_list() {
            self.drive(validator, BeaconParticipant::on_source_header);
        }
    }

    /// Buffer a proven double-vote pair in every participant's
    /// observations, and re-gossip it once, on first sight, so the
    /// evidence reaches every buffer.
    fn observe_vote_equivocation(&mut self, evidence: Box<ShardVoteEquivocation>) {
        let mut first_sight = false;
        for participant in self.participants.values_mut() {
            first_sight |= participant
                .duty
                .observe_vote_equivocation((*evidence).clone());
        }
        if first_sight {
            self.process
                .network
                .broadcast_global(&ShardVoteEquivocationGossip {
                    evidence: Arc::from(evidence),
                });
        }
    }

    /// Hand a commit-proof ask for `source`'s block at `height` to the
    /// lowest registered chain still live on another shard. A loop never
    /// answers for its own shard; with no other, the ask goes nowhere and
    /// `source`'s own certified headers release what waits on it.
    fn route_proof_ask(&mut self, (source, height): (ShardId, BlockHeight)) {
        let Some((&token, (shard, sender))) =
            self.shard_senders.iter().find(|(token, (shard, _))| {
                *shard != source
                    && self
                        .fold
                        .chain(**token)
                        .is_some_and(|chain| !chain.terminal_committed)
            })
        else {
            return;
        };
        let _ = sender.send(HostEvent::protocol(
            *shard,
            ProtocolEvent::CommitProofNeeded {
                source_shard: source,
                block_height: height,
            },
        ));
        self.proof_routes.insert((source, height), token);
    }

    /// The verified proposal a received or fetched one carries. The wire
    /// handler and the fetch's response boundary check a peer's VRF
    /// reveal before handing it over, and the host's own sign and send
    /// seal it, so every proposal reaching the loop keeps its marker; one
    /// that does not is dropped with a warning.
    fn sealed(
        from: ValidatorId,
        proposal: Arc<Verifiable<BeaconProposal>>,
    ) -> Option<Arc<Verified<BeaconProposal>>> {
        let sealed = Arc::unwrap_or_clone(proposal)
            .into_verified()
            .ok()
            .map(Arc::new);
        if sealed.is_none() {
            warn!(?from, "beacon proposal without its check — dropping");
        }
        sealed
    }

    /// Check a gossiped double-vote pair off-thread under the accused
    /// key, resolved from the fold's permanent registry: the head snapshot
    /// may no longer carry a rotated-out signer. The pair authenticates
    /// itself, so no sender is trusted. An unknown validator drops it.
    fn verify_vote_equivocation(&self, evidence: Box<ShardVoteEquivocation>) {
        let Some(pubkey) = self.fold.validator_pubkey(evidence.validator) else {
            warn!("dropping a double-vote pair naming an unregistered validator");
            return;
        };
        let verifier = Arc::clone(&self.process.verifier);
        let network = self.fold.network().clone();
        let beacon_tx = self.process.beacon_event_sender.clone();
        self.process
            .dispatch
            .spawn(DispatchPool::Consensus, move || {
                let holds =
                    verify_shard_vote_equivocation(verifier.as_ref(), &evidence, &network, &pubkey)
                        .is_ok();
                let _ = beacon_tx.send(HostEvent::Beacon(BeaconScopedInput::Continuation {
                    owner: BeaconOwner::Fold,
                    event: Box::new(ProtocolEvent::ShardVoteEquivocationVerified {
                        evidence,
                        verified: holds,
                    }),
                }));
            });
    }

    fn run_fold_actions(&mut self, actions: Vec<Action>) {
        self.actions_generated += actions.len();
        for action in actions {
            self.process_action(BeaconOwner::Fold, action);
        }
    }

    fn run_participant_actions(&mut self, validator: ValidatorId, actions: Vec<Action>) {
        let Some(participant) = self.participants.get(&validator) else {
            return;
        };
        let owner = BeaconOwner::Participant(participant.attachment);
        self.actions_generated += actions.len();
        for action in actions {
            self.process_action(owner, action);
        }
    }

    /// Handle one action the fold or a participant emitted: the loop's
    /// own effects (commit, topology, seat trigger, timer op, catch-up
    /// sync, fetches, commit-proof asks) inline, and every beacon-owned
    /// delegated action on the dispatch pool.
    fn process_action(&mut self, owner: BeaconOwner, action: Action) {
        match action {
            Action::CommitBeaconBlock { block, state } => {
                self.process
                    .beacon_storage
                    .commit_beacon_block(&block, &state);
                // Advance the sync FSM's committed watermark on every commit
                // (gossip or sync) so a serial catch-up unblocks the next
                // epoch's fetch.
                self.on_sync_admitted(block.epoch());
            }
            Action::TopologyChanged { epoch, schedule } => {
                self.process.apply_topology(epoch, Arc::clone(&schedule));
                self.reroute_record_asks();
                for (shard, sender) in self.shard_senders.values() {
                    let _ = sender.send(HostEvent::protocol(
                        *shard,
                        ProtocolEvent::BeaconBlockPersisted {
                            epoch,
                            schedule: Arc::clone(&schedule),
                        },
                    ));
                }
            }
            Action::ReconfigureParticipation(change) => {
                self.pending_participation_changes.push(change);
            }
            Action::SetTimer { id, duration } => match owner {
                BeaconOwner::Participant(attachment) => {
                    self.pending_timer_ops.push(TimerOp::Set {
                        owner: TimerOwner::Participant(attachment),
                        id,
                        duration,
                    });
                }
                BeaconOwner::Fold | BeaconOwner::Chain(_) | BeaconOwner::Submissions => {
                    warn!(
                        ?id,
                        "BeaconLoop: only a participant arms a timer — dropping"
                    );
                }
            },
            Action::CancelTimer { id } => match owner {
                BeaconOwner::Participant(attachment) => {
                    self.pending_timer_ops.push(TimerOp::Cancel {
                        owner: TimerOwner::Participant(attachment),
                        id,
                    });
                }
                BeaconOwner::Fold | BeaconOwner::Chain(_) | BeaconOwner::Submissions => {
                    warn!(
                        ?id,
                        "BeaconLoop: only a participant arms a timer — dropping"
                    );
                }
            },
            Action::StartBeaconBlockSync { target } => {
                self.start_sync(target);
            }
            Action::Fetch(FetchRequest::Ask {
                ids,
                shard,
                preferred,
                class,
            }) => self.ask(owner, ids, shard, preferred, class),
            Action::AbandonFetch(ids) => self.abandon(owner, ids),
            Action::Continuation(ProtocolEvent::CommitProofNeeded {
                source_shard,
                block_height,
            }) => self.route_proof_ask((source_shard, block_height)),
            action @ Action::VerifyBeaconBlock { .. } => self.dispatch_block_check(action),
            other if other.owner() == ActionOwner::Beacon => match owner {
                BeaconOwner::Participant(attachment) => {
                    if self.joins_a_shared_check(attachment, &other) {
                        return;
                    }
                    self.dispatch_participant_action(attachment.validator, other);
                }
                BeaconOwner::Fold | BeaconOwner::Chain(_) | BeaconOwner::Submissions => warn!(
                    action = other.type_name(),
                    "BeaconLoop: a participant action from another owner — dropping"
                ),
            },
            other => warn!(
                action = other.type_name(),
                "BeaconLoop: unexpected beacon action — dropping"
            ),
        }
    }

    /// Whether `action` is a check another participant already runs, which
    /// `attachment` now waits on too. The first to ask runs it.
    fn joins_a_shared_check(&mut self, attachment: Attachment, action: &Action) -> bool {
        let Some(check) = SharedCheck::of_action(action) else {
            return false;
        };
        let waiting = self.shared_checks.entry(check).or_default();
        let joined = !waiting.is_empty();
        waiting.insert(attachment);
        joined
    }

    /// A shared check's outcome: every participant still attached that
    /// waited on it takes it, as if it had run the check itself.
    fn on_shared_check(&mut self, event: ProtocolEvent) {
        let Some(check) = SharedCheck::of_outcome(&event) else {
            return;
        };
        let waiting: Vec<ValidatorId> = self
            .shared_checks
            .remove(&check)
            .unwrap_or_default()
            .into_iter()
            .filter(|attachment| {
                self.participants
                    .get(&attachment.validator)
                    .is_some_and(|p| p.attachment == *attachment)
            })
            .map(|attachment| attachment.validator)
            .collect();
        if let Some((&last, rest)) = waiting.split_last() {
            for &validator in rest {
                self.on_participant_event(validator, event.clone());
            }
            self.on_participant_event(last, event);
        }
    }

    /// Run the fold's block check on the consensus dispatch pool; its
    /// outcome returns to the fold.
    fn dispatch_block_check(&self, action: Action) {
        let handles = Arc::clone(&self.process.dispatch_handles);
        let verifier = Arc::clone(&self.process.verifier);
        let network = self.fold.network().clone();
        let beacon_tx = self.process.beacon_event_sender.clone();
        self.process
            .dispatch
            .spawn(DispatchPool::Consensus, move || {
                let notify = move |event| {
                    let _ = beacon_tx.send(HostEvent::Beacon(BeaconScopedInput::Continuation {
                        owner: BeaconOwner::Fold,
                        event: Box::new(event),
                    }));
                };
                verify_beacon_block(
                    action,
                    verifier.as_ref(),
                    &network,
                    handles.network.as_ref(),
                    &notify,
                );
            });
    }

    /// Run one participant's beacon-owned delegated action on the
    /// consensus dispatch pool, behind its release gate. Its outcomes
    /// return to that participant as continuations.
    fn dispatch_participant_action(&self, validator: ValidatorId, action: Action) {
        let Some(participant) = self.participants.get(&validator) else {
            return;
        };
        let attachment = participant.attachment;
        let handles = Arc::clone(&self.process.dispatch_handles);
        let topology_snapshot = Arc::clone(self.fold.schedule().head());
        let signer = Arc::clone(&participant.signer);
        let gate = Arc::clone(&participant.gate);
        let verifier = Arc::clone(&self.process.verifier);
        let beacon_tx = self.process.beacon_event_sender.clone();
        self.process
            .dispatch
            .spawn(DispatchPool::Consensus, move || {
                let notify: Arc<dyn Fn(ProtocolEvent) + Send + Sync> = Arc::new(move |event| {
                    let _ = beacon_tx.send(HostEvent::Beacon(BeaconScopedInput::Continuation {
                        owner: BeaconOwner::Participant(attachment),
                        event: Box::new(event),
                    }));
                });
                let cache_beacon_proposal =
                    |from: ValidatorId, epoch: Epoch, proposal: Arc<Verified<BeaconProposal>>| {
                        handles.beacon_proposal_cache.admit(from, epoch, proposal);
                    };
                let cache_beacon_candidate = |candidate: Arc<Verified<CandidateBeaconBlock>>| {
                    handles.beacon_candidate_cache.admit(candidate);
                };
                let ctx = BeaconActionContext {
                    topology_snapshot: &topology_snapshot,
                    me: validator,
                    ratify_registers: handles.beacon_storage.as_ref(),
                    beacon_vote_registers: handles.beacon_storage.as_ref(),
                    network: &handles.network,
                    signer: &signer,
                    verifier: verifier.as_ref(),
                    notify,
                    cache_beacon_proposal: &cache_beacon_proposal,
                    cache_beacon_candidate: &cache_beacon_candidate,
                    gate: &gate,
                };
                handle_beacon_action(action, &ctx);
            });
    }

    /// Ask for `ids` on `owner`'s behalf. A witness run goes to its
    /// source shard's committee; a proposal or candidate ask to the
    /// committee of the member it prefers.
    fn ask(
        &mut self,
        owner: BeaconOwner,
        ids: FetchIds,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
    ) {
        let FetchIds::Beacon(ids) = ids else {
            warn!(
                ?ids,
                "BeaconLoop: dropping a fetch the beacon loop does not drive"
            );
            return;
        };
        match ids {
            BeaconFetchIds::Witnesses(ids) => {
                self.ask_for::<ShardWitnessBinding>(owner, ids, shard, preferred, class);
            }
            BeaconFetchIds::Proposals(ids) => {
                if let Some(shard) = self.ask_shard(owner, preferred) {
                    self.ask_for::<BeaconProposalBinding>(owner, ids, shard, preferred, class);
                } else {
                    warn!("BeaconLoop: no live shard with a committee to ask; dropping");
                }
            }
            BeaconFetchIds::Candidates(ids) => {
                if let Some(shard) = self.ask_shard(owner, preferred) {
                    self.ask_for::<BeaconCandidateBinding>(owner, ids, shard, preferred, class);
                } else {
                    warn!("BeaconLoop: no live shard with a committee to ask; dropping");
                }
            }
            BeaconFetchIds::InstanceRecords(_) | BeaconFetchIds::PackageArtifacts(_) => {
                warn_record_fetch(owner);
            }
        }
    }

    fn ask_for<B: Asked>(
        &mut self,
        owner: BeaconOwner,
        ids: Vec<B::Id>,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
    ) {
        let askers = B::askers(&mut self.interest);
        for id in &ids {
            askers.entry(id.clone()).or_default().insert(owner);
        }
        self.drive_fetch::<B>(FetchInput::Request {
            ids,
            shard,
            preferred,
            class,
        });
    }

    /// `owner` no longer wants `ids`. An id another owner still asks for
    /// stays in flight.
    fn abandon(&mut self, owner: BeaconOwner, ids: FetchIds) {
        let FetchIds::Beacon(ids) = ids else {
            return;
        };
        match ids {
            BeaconFetchIds::Witnesses(ids) => self.abandon_for::<ShardWitnessBinding>(owner, ids),
            BeaconFetchIds::Proposals(ids) => self.abandon_for::<BeaconProposalBinding>(owner, ids),
            BeaconFetchIds::Candidates(ids) => {
                self.abandon_for::<BeaconCandidateBinding>(owner, ids);
            }
            BeaconFetchIds::InstanceRecords(_) | BeaconFetchIds::PackageArtifacts(_) => {
                warn_record_fetch(owner);
            }
        }
    }

    fn abandon_for<B: Asked>(&mut self, owner: BeaconOwner, ids: Vec<B::Id>) {
        let askers = B::askers(&mut self.interest);
        let released: Vec<B::Id> = ids
            .into_iter()
            .filter(|id| {
                let Some(owners) = askers.get_mut(id) else {
                    return true;
                };
                owners.remove(&owner);
                let unwanted = owners.is_empty();
                if unwanted {
                    askers.remove(id);
                }
                unwanted
            })
            .collect();
        if !released.is_empty() {
            self.drive_fetch::<B>(FetchInput::Abandoned { ids: released });
        }
    }

    /// Drop every interest `owner` holds in `B`'s ids.
    fn forget<B: Asked>(&mut self, owner: BeaconOwner) {
        let held: Vec<B::Id> = B::askers(&mut self.interest)
            .iter()
            .filter(|(_, owners)| owners.contains(&owner))
            .map(|(id, _)| id.clone())
            .collect();
        self.abandon_for::<B>(owner, held);
    }

    /// A response boundary released `ids`.
    fn release(&mut self, ids: FetchIds, how: Release) {
        let FetchIds::Beacon(ids) = ids else {
            return;
        };
        match ids {
            BeaconFetchIds::Witnesses(ids) => self.release_for::<ShardWitnessBinding>(ids, how),
            BeaconFetchIds::Proposals(ids) => self.release_for::<BeaconProposalBinding>(ids, how),
            BeaconFetchIds::Candidates(ids) => {
                self.release_for::<BeaconCandidateBinding>(ids, how);
            }
            BeaconFetchIds::InstanceRecords(ids) => {
                self.release_for::<InstanceRecordBinding>(ids, how);
            }
            BeaconFetchIds::PackageArtifacts(ids) => {
                self.release_for::<PackageArtifactBinding>(ids, how);
            }
        }
    }

    fn release_for<B: Asked>(&mut self, ids: Vec<B::Id>, how: Release) {
        if how == Release::Admitted {
            let askers = B::askers(&mut self.interest);
            for id in &ids {
                askers.remove(id);
            }
        }
        self.drive_fetch::<B>(how.input(ids));
    }

    /// Feed `B`'s fetch an input and send what it emits.
    fn drive_fetch<B: FetchedBy<BeaconFetchState>>(&mut self, input: FetchInput<B::Id>) {
        let outputs = B::fetch_mut(&mut self.fetches).handle(input);
        let network = &*self.process.network;
        for FetchOutput::Send { ids, route } in outputs {
            if B::PER_ID {
                for id in ids {
                    B::dispatch_chunk(vec![id], route, network, &self.reply);
                }
            } else {
                B::dispatch_chunk(ids, route, network, &self.reply);
            }
        }
    }

    /// Keep the loop's one fetch tick armed exactly while its fetches or
    /// its catch-up sync have work pending, or a submission waits to be
    /// swept at its window's end.
    fn update_fetch_tick_timer(&mut self) {
        let pending = self.fetches.has_pending()
            || beacon::has_pending(&self.beacon_block)
            || !self.submissions.is_empty();
        if let Some(op) = self
            .fetch_tick
            .refresh(TimerOwner::Beacon, self.now, pending)
        {
            self.pending_timer_ops.push(op);
        }
    }

    /// The shard a participant's ask goes to: the shard of the member it
    /// prefers, whose committee holds that member, or a live leaf by
    /// [`Self::fetch_shard`] spread by the asker when the member sits on
    /// no live shard with a committee.
    fn ask_shard(&self, owner: BeaconOwner, preferred: Option<ValidatorId>) -> Option<ShardId> {
        let topology = self.process.topology_snapshot.load();
        let asker = match owner {
            BeaconOwner::Participant(attachment) => attachment.validator.inner(),
            BeaconOwner::Fold | BeaconOwner::Chain(_) | BeaconOwner::Submissions => 0,
        };
        preferred
            .and_then(
                |member| match self.fold.state().validators.get(&member)?.status {
                    ValidatorStatus::OnShard { shard, .. } => Some(shard),
                    _ => None,
                },
            )
            .filter(|&shard| answers(&topology, shard))
            .or_else(|| self.fetch_shard(asker))
    }

    /// Pick a shard whose committee a beacon ask goes to. Every shard
    /// member holds the beacon chain, so any live leaf with a committee
    /// answers; spreading by `spread` keeps a host's asks from all
    /// hammering one committee.
    fn fetch_shard(&self, spread: u64) -> Option<ShardId> {
        let topology = self.process.topology_snapshot.load();
        let leaves: Vec<ShardId> = topology
            .shard_trie()
            .leaves()
            .filter(|&leaf| answers(&topology, leaf))
            .collect();
        if leaves.is_empty() {
            return None;
        }
        let idx = usize::try_from(spread % leaves.len() as u64)
            .expect("modulo of leaves.len() fits usize");
        Some(leaves[idx])
    }
}

/// A record or artifact is wanted by a chain's loop through
/// [`BeaconInput::RecordsWanted`], which tells it when each arrives; the
/// fold and the participants want none, so a fetch action naming one is
/// dropped.
fn warn_record_fetch(owner: BeaconOwner) {
    warn!(
        ?owner,
        "BeaconLoop: a record fetch from a beacon owner — dropping"
    );
}

/// The host's fold, resumed from its beacon storage's committed tip with
/// the windows no chain yet holds open, its clock at `now`.
///
/// # Panics
///
/// Panics if `storage` holds no committed block — every host commits the
/// genesis pair before it builds its fold.
pub(crate) fn resume_fold(
    storage: &dyn BeaconStorage,
    verifier: Arc<dyn Verifier>,
    network: NetworkDefinition,
    config_hash: GenesisConfigHash,
    now: LocalTimestamp,
) -> BeaconFold {
    let (latest_block, latest_state) = storage
        .latest_committed()
        .expect("beacon chain is non-empty after the genesis commit");
    let history = storage.states_since(retention_floor(&latest_state, None, now));
    let mut fold = BeaconFold::new(verifier, latest_block, history, network, config_hash);
    fold.set_now(now);
    fold
}

/// Close every participant's release gate on every way the loop goes
/// away: a teardown, a panic unwinding its thread, or a crashed host.
impl<S, N, D> Drop for BeaconLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    fn drop(&mut self) {
        for participant in self.participants.values() {
            participant.gate.close_and_wait();
        }
    }
}

/// A peer item check whose outcome depends on the item and the fold alone,
/// keyed as each participant keys its own check slot: a ratify vote by
/// its signer's seat in a round, a candidate by its block hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SharedCheck {
    RatifyVote(RatifyVoteSlotKey),
    Candidate(BeaconBlockHash),
}

impl SharedCheck {
    fn of_action(action: &Action) -> Option<Self> {
        match action {
            Action::VerifyRatifyVote { vote, .. } => Some(Self::RatifyVote((
                vote.anchor_hash(),
                vote.epoch(),
                vote.round(),
                vote.phase(),
                vote.signer(),
            ))),
            Action::VerifyBeaconCandidate { candidate, .. } => {
                Some(Self::Candidate(candidate.block_hash()))
            }
            _ => None,
        }
    }

    const fn of_outcome(event: &ProtocolEvent) -> Option<Self> {
        match *event {
            ProtocolEvent::RatifyVoteVerified {
                anchor,
                epoch,
                round,
                phase,
                signer,
                ..
            } => Some(Self::RatifyVote((anchor, epoch, round, phase, signer))),
            ProtocolEvent::BeaconCandidateVerified { block_hash, .. } => {
                Some(Self::Candidate(block_hash))
            }
            _ => None,
        }
    }
}

/// Whether a beacon ask over `shard` reaches anyone: a live leaf with a
/// committee.
fn answers(topology: &TopologySnapshot, shard: ShardId) -> bool {
    topology.shard_trie().contains(shard) && !topology.committee_for_shard(shard).is_empty()
}

/// Who still wants each id of one fetch. An id is released only when the
/// last owner asking for it abandons it.
type Askers<Id> = BTreeMap<Id, BTreeSet<BeaconOwner>>;

/// The owners asking each id the loop fetches. The entry's route,
/// in-flight slot, failure count and tick hold stay one per id in
/// [`BeaconFetchState`], shared by every owner that wants it.
#[derive(Default)]
struct Interest {
    witnesses: Askers<(ShardId, BlockHeight, BlockHash, LeafIndex, LeafIndex)>,
    proposals: Askers<(Epoch, ValidatorId)>,
    candidates: Askers<(Epoch, BeaconBlockHash)>,
    records: Askers<Address>,
    packages: Askers<Hash>,
}

/// A beacon fetch the loop drives on behalf of several owners.
trait Asked: FetchedBy<BeaconFetchState> {
    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id>;
}

impl Asked for ShardWitnessBinding {
    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id> {
        &mut interest.witnesses
    }
}

impl Asked for BeaconProposalBinding {
    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id> {
        &mut interest.proposals
    }
}

impl Asked for BeaconCandidateBinding {
    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id> {
        &mut interest.candidates
    }
}

/// The beacon-block catch-up sync: the loop feeds its FSM and turns the
/// FSM's fetches into requests past the host.
impl<S, N, D> BeaconLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Begin (or extend) a catch-up sync toward `target`, fetching above
    /// the committed watermark.
    fn start_sync(&mut self, target: Epoch) {
        let outputs = self
            .beacon_block
            .handle(BeaconBlockSyncInput::StartSync { scope: (), target });
        self.drive_sync(outputs);
    }

    /// A beacon-block sync response landed, for the epoch it was asked
    /// for: the response boundary drops a block naming any other. `None`
    /// (the peer does not hold the epoch) re-queues through the failure
    /// path. Otherwise the block
    /// goes to the fold and the FSM learns the epoch's bytes arrived.
    ///
    /// `FetchSucceeded` means "the bytes arrived", not "the block is
    /// valid": the fold verifies against the committee it owns. The FSM
    /// parks the epoch in `pending_admission`; a valid block commits and
    /// feeds `Admitted`, while one that fails verification is never
    /// admitted, so the FSM re-fetches it from another peer after
    /// `PENDING_ADMISSION_TIMEOUT` rather than this path duplicating
    /// committee-aware verification.
    fn on_sync_response(
        &mut self,
        epoch: Epoch,
        block: Option<Arc<Verifiable<CertifiedBeaconBlock>>>,
    ) {
        let Some(block) = block else {
            // Back off rather than re-queue immediately: the sync target
            // comes from an unverified gossip block, so a bogus far-future
            // epoch would otherwise busy-loop the network fetching an epoch
            // nobody has produced.
            self.on_sync_fetch_failed(epoch, FetchFailureKind::NotFound);
            return;
        };
        let actions = self.fold.on_beacon_block_received(block);
        self.run_fold_actions(actions);
        let outputs = self
            .beacon_block
            .handle(BeaconBlockSyncInput::FetchSucceeded {
                scope: (),
                from: epoch,
                count: 1,
                delivered_heights: vec![epoch],
                now: self.now,
            });
        self.drive_sync(outputs);
    }

    /// Re-queue an epoch through `FetchFailed`, under the FSM's deferral
    /// for `kind`.
    fn on_sync_fetch_failed(&mut self, epoch: Epoch, kind: FetchFailureKind) {
        let outputs = self.beacon_block.handle(BeaconBlockSyncInput::FetchFailed {
            scope: (),
            from: epoch,
            count: 1,
            kind,
            now: self.now,
        });
        self.drive_sync(outputs);
    }

    /// Advance the FSM's committed watermark to `epoch` on a beacon commit
    /// (gossip or sync), so a serial catch-up unblocks the next epoch's
    /// fetch.
    fn on_sync_admitted(&mut self, epoch: Epoch) {
        let outputs = self.beacon_block.handle(BeaconBlockSyncInput::Admitted {
            scope: (),
            height: epoch,
        });
        self.drive_sync(outputs);
    }

    /// Re-dispatch any deferred fetch whose backoff has expired.
    fn on_sync_tick(&mut self) {
        let outputs = self
            .beacon_block
            .handle(BeaconBlockSyncInput::Tick { now: self.now });
        self.drive_sync(outputs);
    }

    /// Turn the FSM's scheduling outputs into network fetches. A fetch no
    /// live shard can answer goes back to the FSM as `NoPeers`, so its
    /// slot frees and the backoff retries it on a later tick. The beacon
    /// has no sync mode to exit (each adopted block already re-arms the
    /// participants' timers), so completion is informational.
    fn drive_sync(&mut self, outputs: Vec<BeaconBlockSyncOutput>) {
        for output in outputs {
            match output {
                SyncOutput::Fetch { from, .. } => {
                    if !self.dispatch_sync_fetch(from) {
                        self.on_sync_fetch_failed(from, FetchFailureKind::NoPeers);
                    }
                }
                SyncOutput::Complete { height, .. } => {
                    tracing::info!(epoch = height.inner(), "Beacon block sync complete");
                }
            }
        }
    }

    /// Ask past the host for `epoch`: its own beacon store is filled by
    /// the same commits the sync is waiting on. Whether a live shard with
    /// a committee took the ask. The leaf asked moves with every ask,
    /// spread by the host's lowest identity and [`Self::sync_spread`].
    fn dispatch_sync_fetch(&mut self, epoch: Epoch) -> bool {
        let lowest = self.validators().next().map_or(0, ValidatorId::inner);
        self.sync_spread = self.sync_spread.wrapping_add(1);
        let Some(shard) = self.fetch_shard(lowest.wrapping_add(self.sync_spread)) else {
            warn!("BeaconLoop: no live shard to fetch beacon blocks from; deferring");
            return false;
        };
        let beacon_tx = self.process.beacon_event_sender.clone();
        self.process.network.request_from(
            shard,
            Answerers::PeersOnly,
            None,
            GetBeaconBlockRequest::new(epoch),
            None,
            Box::new(
                move |result: Result<GetBeaconBlockResponse, RequestError>| {
                    let (input, verdict) = match result {
                        // A block for another epoch is no answer for this
                        // one, and only a peer making it up gives it.
                        Ok(resp) if resp.block.as_ref().is_some_and(|b| b.epoch() != epoch) => {
                            warn!(
                                epoch = epoch.inner(),
                                "beacon sync answer names another epoch — dropping"
                            );
                            (
                                BeaconScopedInput::BeaconBlockSyncFetchFailed {
                                    epoch,
                                    kind: FetchFailureKind::NotFound,
                                },
                                ResponseVerdict::Reject,
                            )
                        }
                        // "Peer doesn't have this epoch" is ambiguous (it
                        // may be behind us) — never Reject.
                        Ok(resp) => (
                            BeaconScopedInput::BeaconBlockSyncResponseReceived {
                                epoch,
                                block: resp.block,
                            },
                            ResponseVerdict::Accept,
                        ),
                        Err(err) => (
                            BeaconScopedInput::BeaconBlockSyncFetchFailed {
                                epoch,
                                kind: classify_fetch_error(&err),
                            },
                            ResponseVerdict::Accept,
                        ),
                    };
                    let _ = beacon_tx.send(HostEvent::Beacon(input));
                    verdict
                },
            ),
        );
        true
    }
}

#[cfg(test)]
mod tests;
