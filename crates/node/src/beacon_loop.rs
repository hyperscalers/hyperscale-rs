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
use hyperscale_beacon::{
    Adopted, BeaconFold, BeaconParticipant, ChainRegistration, ParticipantStep,
};
use hyperscale_core::{
    Action, ActionOwner, BeaconActionContext, BeaconFetchIds, FetchIds, FetchRequest,
    ParticipationChange, ProtocolEvent, SignerGate,
};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_network::{Answerers, Network, RequestError, ResponseVerdict};
use hyperscale_storage::{BeaconStorage, ShardStorage};
use hyperscale_types::network::gossip::ShardVoteEquivocationGossip;
use hyperscale_types::network::request::beacon::GetBeaconBlockRequest;
use hyperscale_types::network::response::beacon::GetBeaconBlockResponse;
use hyperscale_types::{
    BeaconBlockHash, BeaconProposal, BeaconProposalVerifyContext, BeaconState, BlockHash,
    BlockHeight, CandidateBeaconBlock, CertifiedBeaconBlock, CertifiedBlockHeader, Epoch,
    GenesisConfigHash, LeafIndex, LocalTimestamp, MessageClass, NetworkDefinition, ShardId,
    ShardVoteEquivocation, Signer, TopologySchedule, TopologySnapshot, ValidatorId,
    ValidatorStatus, Verifiable, Verified, Verifier, Verify, verify_shard_vote_equivocation,
};
use tracing::warn;

use crate::beacon::{
    self, BeaconBlockSync, BeaconBlockSyncInput, BeaconBlockSyncOutput, BeaconCandidateBinding,
    BeaconFetchState, BeaconProposalBinding, BeaconReply, ShardWitnessBinding,
};
use crate::config::NodeConfig;
use crate::event::{
    Attachment, BeaconInput, BeaconOwner, BeaconScopedInput, FetchFailureKind, HostEvent,
    Registration, classify_fetch_error,
};
use crate::fetch::{FetchInput, FetchOutput, FetchedBy, Release};
use crate::process::ProcessIo;
use crate::shard::{FetchTicker, StepOutput, TimerOp, TimerOwner};
use crate::sync::SyncOutput;

/// The host's beacon driver.
pub struct BeaconLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    /// Process-scoped resources shared with every other driver on the host:
    /// beacon storage, the topology `ArcSwap`, the dispatch pool.
    pub(crate) process: Arc<ProcessIo<S, N, D>>,

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
    pub(crate) pending_participation_changes: Vec<ParticipationChange>,

    /// Per-step scratch: every certified header a chain loop reported this
    /// step, its own or a remote shard's, for a host that summarises them
    /// ([`Self::take_admitted`]). Cleared at step entry, so a host that never
    /// drains it holds one step's worth at most.
    pending_admitted: Vec<Arc<Verified<CertifiedBlockHeader>>>,

    /// Per-step scratch: timer operations, each owned by the participant
    /// that armed it or by the loop for its fetch tick.
    pub(crate) pending_timer_ops: Vec<TimerOp>,

    /// Per-step scratch: count of actions the fold and participants
    /// produced.
    pub(crate) actions_generated: usize,

    /// Beacon-block catch-up sync, scope `()`. The fold emits
    /// `Action::StartBeaconBlockSync` when a gossiped block sits more than
    /// one epoch ahead of its tip; this FSM drives the
    /// `GetBeaconBlockRequest` fetches that close the gap.
    beacon_block: BeaconBlockSync,

    /// The witness, proposal and candidate fetches the fold and the
    /// participants ask for.
    fetches: BeaconFetchState,

    /// Which owners want each fetched id.
    interest: Interest,

    /// Where the fetches' answers return: the host's beacon channel.
    reply: BeaconReply,

    /// The one fetch tick that retries both the fetches and the sync.
    fetch_tick: FetchTicker,
}

/// One identity's beacon participation on the loop.
struct Participant {
    attachment: Attachment,
    duty: BeaconParticipant,
    signer: Arc<dyn Signer>,
    /// The release gate every signature the participant dispatches
    /// enters, closed when the participant is removed.
    gate: Arc<SignerGate>,
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
            reply: BeaconReply(process.beacon_event_sender.clone()),
            process,
            fold,
            participants: BTreeMap::new(),
            shard_senders: BTreeMap::new(),
            proof_routes: BTreeMap::new(),
            now,
            pending_participation_changes: Vec::new(),
            pending_admitted: Vec::new(),
            pending_timer_ops: Vec::new(),
            actions_generated: 0,
            beacon_block,
            fetches: BeaconFetchState::new(config),
            interest: Interest::default(),
            fetch_tick: FetchTicker::default(),
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
            let history = states_since(self.process.beacon_storage.as_ref(), floor);
            self.fold.widen(&history);
        }
        let token = self.fold.register_chain(shard, anchors, height);
        self.shard_senders.insert(token, (shard, sender));
        Registration {
            token,
            schedule: Arc::new(self.fold.schedule().clone()),
            epoch: self.fold.state().current_epoch,
            chain_config: self.fold.state().chain_config,
        }
    }

    /// Stop tracking the chain `token` names. The commit-proof asks its
    /// loop held go to another registered loop.
    pub(crate) fn deregister(&mut self, token: ChainRegistration) {
        self.fold.deregister_chain(token);
        self.shard_senders.remove(&token);
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
    /// resumed from its durable ratification record. Its startup timers
    /// land in the timer scratch for the caller to drain. No-op if the
    /// loop already runs it.
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
                gate: Arc::new(SignerGate::new()),
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
    /// Re-arming is idempotent: it replaces the pending fire at the
    /// runner's table with one at the same deadline.
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

    /// The topology schedule the fold keeps: every retained epoch's
    /// committees, by which a reported header's signers resolve.
    #[must_use]
    pub const fn schedule(&self) -> &TopologySchedule {
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
            BeaconScopedInput::BeaconBlockSyncResponseReceived { epoch, block } => {
                self.on_sync_response(epoch, block);
            }
            BeaconScopedInput::BeaconBlockSyncFetchFailed { epoch, kind } => {
                self.on_sync_fetch_failed(epoch, kind);
            }
            BeaconScopedInput::FetchFailed(ids) => self.release(ids, Release::Failed),
            BeaconScopedInput::FetchUnroutable(ids) => self.release(ids, Release::Unroutable),
            BeaconScopedInput::Answered { ids, event } => self.on_answer(ids, *event),
            BeaconScopedInput::FetchTick => {
                self.fetch_tick.fired();
                self.drive_fetch::<ShardWitnessBinding>(FetchInput::Tick);
                self.drive_fetch::<BeaconProposalBinding>(FetchInput::Tick);
                self.drive_fetch::<BeaconCandidateBinding>(FetchInput::Tick);
                self.on_sync_tick();
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
                if let Some(proposal) = self.verify_proposal(from, epoch, proposal) {
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

    /// A fetch's answer. Its ids retire before what it carries is taken,
    /// so the freed capacity is there for any fetch that re-drives. A
    /// witness run the fold refuses releases its ids as failed instead,
    /// which retries it at once the first time and on the tick after.
    fn on_answer(&mut self, ids: FetchIds, event: ProtocolEvent) {
        let ProtocolEvent::ShardWitnessesReceived {
            shard_id,
            committed_block_hash,
            lo,
            payloads,
            range_proof,
        } = event
        else {
            self.release(ids, Release::Admitted);
            self.on_protocol(event);
            return;
        };
        match self.fold.on_shard_witnesses_received(
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
        }
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
            ProtocolEvent::UnverifiedPcVote1Received { view, vote } => {
                self.drive(validator, |p, _| p.on_pc_vote1_received(view, vote));
            }
            ProtocolEvent::UnverifiedPcVote2Received { view, vote } => {
                self.drive(validator, |p, _| p.on_pc_vote2_received(view, vote));
            }
            ProtocolEvent::UnverifiedPcVote3Received { view, vote } => {
                self.drive(validator, |p, _| p.on_pc_vote3_received(view, vote));
            }
            ProtocolEvent::VerifiedPcVote1Received { view, vote } => {
                self.drive(validator, |p, fold| {
                    p.on_verified_pc_vote1_received(fold, view, vote)
                });
            }
            ProtocolEvent::VerifiedPcVote2Received { view, vote } => {
                self.drive(validator, |p, fold| {
                    p.on_verified_pc_vote2_received(fold, view, vote)
                });
            }
            ProtocolEvent::VerifiedPcVote3Received { view, vote } => {
                self.drive(validator, |p, fold| {
                    p.on_verified_pc_vote3_received(fold, view, vote)
                });
            }
            ProtocolEvent::SpcNewViewReceived { from, proposal } => {
                self.drive(validator, |p, _| p.on_spc_new_view_received(from, proposal));
            }
            ProtocolEvent::SpcNewCommitReceived { from, msg } => {
                self.drive(validator, |p, _| p.on_spc_new_commit_received(from, msg));
            }
            ProtocolEvent::UnverifiedSpcEmptyViewReceived { msg } => {
                self.drive(validator, |p, _| {
                    p.on_unverified_spc_empty_view_received(msg)
                });
            }
            ProtocolEvent::VerifiedSpcEmptyViewReceived { msg } => {
                self.drive(validator, |p, fold| {
                    p.on_verified_spc_empty_view_received(fold, msg)
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
                if let Some(proposal) = self.verify_proposal(from, epoch, proposal) {
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
            ProtocolEvent::BeaconCandidateVerified { result } => {
                self.drive(validator, |p, fold| {
                    p.on_beacon_candidate_verified(fold, result)
                });
            }
            ProtocolEvent::BeaconProposalFetched {
                epoch,
                validator: author,
                proposal,
            } => {
                self.drive(validator, |p, fold| {
                    p.on_beacon_proposal_fetched(fold, epoch, author, proposal)
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
        let Adopted { effects, actions } = adopted;
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

    /// Lift a gossiped proposal to verified, VRF-checking it against its
    /// sender's key when the marker isn't already live.
    ///
    /// A sealed proposal goes straight through: this host's own sign and
    /// send produced the reveal, and a colocated sender's notification
    /// keeps the marker because `notify` hands local recipients the
    /// in-memory message. An unsealed proposal from a sender the fold
    /// does not know, or whose reveal fails, is dropped with a warning.
    fn verify_proposal(
        &self,
        from: ValidatorId,
        epoch: Epoch,
        proposal: Arc<Verifiable<BeaconProposal>>,
    ) -> Option<Arc<Verified<BeaconProposal>>> {
        let raw = match Arc::unwrap_or_clone(proposal).into_verified() {
            Ok(verified) => return Some(Arc::new(verified)),
            Err(raw) => raw,
        };
        let Some(record) = self.fold.state().validators.get(&from) else {
            warn!(
                ?from,
                "BeaconProposalReceived from validator not in BeaconState — dropping",
            );
            return None;
        };
        let ctx = BeaconProposalVerifyContext {
            verifier: self.fold.verifier().as_ref(),
            network: self.fold.network(),
            epoch,
            sender_pk: record.pubkey,
        };
        match raw.verify(&ctx) {
            Ok(verified) => Some(Arc::new(verified)),
            Err(err) => {
                warn!(
                    ?from,
                    epoch = epoch.inner(),
                    ?err,
                    "BeaconProposalReceived VRF verification failed — dropping",
                );
                None
            }
        }
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
                BeaconOwner::Fold => warn!(?id, "BeaconLoop: the fold arms no timer — dropping"),
            },
            Action::CancelTimer { id } => match owner {
                BeaconOwner::Participant(attachment) => {
                    self.pending_timer_ops.push(TimerOp::Cancel {
                        owner: TimerOwner::Participant(attachment),
                        id,
                    });
                }
                BeaconOwner::Fold => warn!(?id, "BeaconLoop: the fold arms no timer — dropping"),
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
                    self.dispatch_participant_action(attachment.validator, other);
                }
                BeaconOwner::Fold => warn!(
                    action = other.type_name(),
                    "BeaconLoop: a participant action from the fold — dropping"
                ),
            },
            other => warn!(
                action = other.type_name(),
                "BeaconLoop: unexpected beacon action — dropping"
            ),
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
    /// its catch-up sync have work pending.
    fn update_fetch_tick_timer(&mut self) {
        let pending = self.fetches.has_pending() || beacon::has_pending(&self.beacon_block);
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
            BeaconOwner::Participant(attachment) => Some(attachment.validator),
            BeaconOwner::Fold => None,
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
    fn fetch_shard(&self, spread: Option<ValidatorId>) -> Option<ShardId> {
        let topology = self.process.topology_snapshot.load();
        let leaves: Vec<ShardId> = topology
            .shard_trie()
            .leaves()
            .filter(|&leaf| answers(&topology, leaf))
            .collect();
        if leaves.is_empty() {
            return None;
        }
        let spread = spread.map_or(0, ValidatorId::inner);
        let idx = usize::try_from(spread % leaves.len() as u64)
            .expect("modulo of leaves.len() fits usize");
        Some(leaves[idx])
    }
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
    let history = states_since(storage, retention_floor(&latest_state, None, now));
    let mut fold = BeaconFold::new(verifier, latest_block, history, network, config_hash);
    fold.set_now(now);
    fold
}

/// The states beacon storage holds from `floor` on, oldest first.
fn states_since(storage: &dyn BeaconStorage, floor: Epoch) -> Vec<BeaconState> {
    storage
        .states_since(floor)
        .into_iter()
        .map(|state| state.as_ref().clone())
        .collect()
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

    /// A beacon-block sync response landed. `None` (the peer does not hold
    /// the epoch) re-queues through the failure path. Otherwise the block
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
    /// a committee took the ask.
    fn dispatch_sync_fetch(&self, epoch: Epoch) -> bool {
        let lowest = self.validators().next();
        let Some(shard) = self.fetch_shard(lowest) else {
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
                    let input = match result {
                        Ok(resp) => BeaconScopedInput::BeaconBlockSyncResponseReceived {
                            epoch,
                            block: resp.block,
                        },
                        Err(err) => BeaconScopedInput::BeaconBlockSyncFetchFailed {
                            epoch,
                            kind: classify_fetch_error(&err),
                        },
                    };
                    let _ = beacon_tx.send(HostEvent::Beacon(input));
                    // "Peer doesn't have this epoch" is ambiguous (it may be
                    // behind us) — never Reject.
                    ResponseVerdict::Accept
                },
            ),
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crossbeam::channel::{Receiver, unbounded};
    use hyperscale_core::TimerId;
    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_dispatch_sync::{DeferredJobs, ProcessingTimes, SyncDispatch};
    use hyperscale_network_memory::{
        HostLayout, LinkStreams, NetworkConfig, SimNetworkAdapter, SimulatedNetwork,
    };
    use hyperscale_storage::RecoveredState;
    use hyperscale_storage::test_helpers::commit_one;
    use hyperscale_types::network::request::beacon::GetBeaconProposalRequest;
    use hyperscale_types::network::response::beacon::GetBeaconProposalResponse;
    use hyperscale_types::test_utils::{certify, make_live_block, test_transaction};
    use hyperscale_types::{
        AggregateSignature, BeaconBlock, BeaconCert, BeaconChainConfig, BeaconProposalDraft,
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHeader, BlockHeaderParts, BlockHeight,
        BlockVote, CertifiedBlock, CertifiedBlockHeader, Hash, ProposerTimestamp,
        QuorumCertificate, RatifyCert, RatifyRound, Round, SignerBitfield, TopologySchedule,
        VrfProof, WeightedTimestamp, shard_prefix_path,
    };

    use super::*;
    use crate::HostedChain;
    use crate::shard::test_host::{Fixture, Host, SHARD, loop_of};
    use crate::shard::{ShardScopedInput, ThreadShardLoop};

    type Loop = BeaconLoop<SimShardStorage, SimNetworkAdapter, SyncDispatch>;

    use hyperscale_storage_memory::{SimShardStorage, crash_point};

    const PROPOSAL: (Epoch, ValidatorId) = (Epoch::new(1), ValidatorId::new(1));

    fn participant(n: u64) -> BeaconOwner {
        BeaconOwner::Participant(Attachment::new(ValidatorId::new(n), n))
    }

    fn proposals(ids: &[(Epoch, ValidatorId)]) -> FetchIds {
        FetchIds::Beacon(BeaconFetchIds::Proposals(ids.to_vec()))
    }

    /// `owner` asks for `ids` through the loop, as its participant would.
    fn ask(beacon: &mut Loop, owner: BeaconOwner, ids: &[(Epoch, ValidatorId)]) {
        beacon.ask(owner, proposals(ids), ShardId::ROOT, None, None);
    }

    fn in_flight(beacon: &Loop) -> usize {
        beacon.fetches.beacon_proposal.in_flight_count()
    }

    fn fetch_ticks(ops: &[TimerOp]) -> Vec<bool> {
        ops.iter()
            .filter_map(|op| match op {
                TimerOp::Set {
                    owner: TimerOwner::Beacon,
                    id: TimerId::FetchTick,
                    ..
                } => Some(true),
                TimerOp::Cancel {
                    owner: TimerOwner::Beacon,
                    id: TimerId::FetchTick,
                } => Some(false),
                _ => None,
            })
            .collect()
    }

    fn attachment(host: &Host, idx: usize, fix: &Fixture) -> Attachment {
        host.beacon.participants[&fix.committee.validator_id(idx)].attachment
    }

    /// A host with no participant still runs its beacon loop: the loop
    /// asks for what an owner wants and arms its own fetch tick.
    #[test]
    fn every_host_runs_a_beacon_loop_with_no_participant() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        assert_eq!(host.participants().count(), 0);
        ask(&mut host.beacon, participant(2), &[PROPOSAL]);
        assert!(host.beacon.fetches.has_pending());
        host.beacon.update_fetch_tick_timer();
        let out = host.drain_pending_output();
        assert_eq!(fetch_ticks(&out.timer_ops), vec![true]);
        let out = host.step(HostEvent::beacon_fetch_tick());
        assert_eq!(
            fetch_ticks(&out.timer_ops),
            vec![true],
            "the tick fires on the beacon loop and re-arms while the ask is pending",
        );
    }

    /// One participant's abandon releases nothing another still wants;
    /// the last abandon releases the id.
    #[test]
    fn a_participant_abandoning_a_fetch_keeps_a_siblings_interest() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        let beacon = &mut host.beacon;
        ask(beacon, participant(2), &[PROPOSAL]);
        ask(beacon, participant(3), &[PROPOSAL]);
        beacon.abandon(participant(2), proposals(&[PROPOSAL]));
        assert_eq!(
            beacon.fetches.beacon_proposal.pending_count(),
            1,
            "a sibling still wants the proposal",
        );
        beacon.abandon(participant(3), proposals(&[PROPOSAL]));
        assert_eq!(beacon.fetches.beacon_proposal.pending_count(), 0);
    }

    /// An id held after two failures since the tick stays held when a
    /// second participant asks for it: the hold is the entry's, not the
    /// asker's.
    #[test]
    fn a_second_owner_asking_for_a_held_id_does_not_lift_its_hold() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        let beacon = &mut host.beacon;
        ask(beacon, participant(2), &[PROPOSAL]);
        beacon.release(proposals(&[PROPOSAL]), Release::Failed);
        beacon.release(proposals(&[PROPOSAL]), Release::Failed);
        assert_eq!(in_flight(beacon), 0, "a second failure holds the id");
        ask(beacon, participant(3), &[PROPOSAL]);
        assert_eq!(
            in_flight(beacon),
            0,
            "a second asker does not lift the hold"
        );
        beacon.dispatch_event(BeaconScopedInput::FetchTick);
        assert_eq!(in_flight(beacon), 1, "the tick lifts it");
    }

    /// A witness run the fold refuses is released as failed rather than
    /// retired: it is asked again at once the first time and, refused
    /// again, waits for the tick, so a run served the same way each time
    /// costs one retry a tick instead of one per refusal.
    #[test]
    fn a_refused_witness_run_retries_once_and_then_on_the_tick() {
        use hyperscale_types::{ShardWitnessPayload, Stake, StakePoolId};

        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        let _ = host.beacon.fold.set_host_on_committee(true);
        let anchor = BlockHash::from_raw(Hash::from_bytes(b"unheld anchor"));
        let run = (
            SHARD,
            BlockHeight::new(5),
            anchor,
            LeafIndex::new(0),
            LeafIndex::new(1),
        );
        let ids = || FetchIds::Beacon(BeaconFetchIds::Witnesses(vec![run]));
        host.beacon.ask(BeaconOwner::Fold, ids(), SHARD, None, None);
        let in_flight = |beacon: &Loop| beacon.fetches.shard_witness.in_flight_count();
        assert_eq!(in_flight(&host.beacon), 1);
        let refused = || BeaconScopedInput::Answered {
            ids: ids(),
            event: Box::new(ProtocolEvent::ShardWitnessesReceived {
                shard_id: SHARD,
                committed_block_hash: anchor,
                lo: LeafIndex::new(0),
                payloads: vec![ShardWitnessPayload::StakeDeposit {
                    pool_id: StakePoolId::new(0),
                    amount: Stake::from_whole_tokens(1),
                }],
                range_proof: Vec::new(),
            }),
        };

        host.beacon.dispatch_event(refused());
        assert_eq!(in_flight(&host.beacon), 1, "the first refusal asks again");
        host.beacon.dispatch_event(refused());
        assert_eq!(in_flight(&host.beacon), 0, "the second waits for the tick");
        assert_eq!(host.beacon.fetches.shard_witness.pending_count(), 1);
        host.beacon.dispatch_event(BeaconScopedInput::FetchTick);
        assert_eq!(in_flight(&host.beacon), 1, "the tick asks again");
    }

    /// The loop's own tick retries a held proposal fetch whether or not a
    /// block sync runs.
    #[test]
    fn a_held_proposal_fetch_retries_on_the_loops_tick_with_no_block_sync() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        ask(&mut host.beacon, participant(2), &[PROPOSAL]);
        host.beacon.release(proposals(&[PROPOSAL]), Release::Failed);
        host.beacon.release(proposals(&[PROPOSAL]), Release::Failed);
        assert_eq!(in_flight(&host.beacon), 0);
        assert!(!beacon::has_pending(&host.beacon.beacon_block));
        let _ = host.step(HostEvent::beacon_fetch_tick());
        assert_eq!(in_flight(&host.beacon), 1);
    }

    /// The loop's tick is armed while a fetch or the catch-up sync has
    /// work, and cancelled once neither has.
    #[test]
    fn the_beacon_loops_tick_is_armed_only_while_a_fetch_or_sync_is_pending() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        let _ = host.drain_pending_output();

        ask(&mut host.beacon, participant(2), &[PROPOSAL]);
        host.beacon.update_fetch_tick_timer();
        assert_eq!(
            fetch_ticks(&host.drain_pending_output().timer_ops),
            vec![true],
            "a pending fetch arms the tick",
        );
        let out = host.step(HostEvent::Beacon(BeaconScopedInput::Answered {
            ids: proposals(&[PROPOSAL]),
            event: Box::new(ProtocolEvent::BeaconRatifyTimer),
        }));
        assert_eq!(
            fetch_ticks(&out.timer_ops),
            vec![false],
            "an answered fetch leaves nothing pending",
        );

        host.beacon.start_sync(Epoch::new(5));
        host.beacon.update_fetch_tick_timer();
        assert_eq!(
            fetch_ticks(&host.drain_pending_output().timer_ops),
            vec![true],
            "a running sync keeps the tick armed",
        );
        let out = host.step(HostEvent::Beacon(BeaconScopedInput::Protocol(Box::new(
            ProtocolEvent::BeaconRatifyTimer,
        ))));
        assert!(
            fetch_ticks(&out.timer_ops).is_empty(),
            "a step while the armed tick is not yet due leaves it be",
        );
    }

    /// A live leaf with no committee answers nothing, so no spread lands
    /// on one.
    #[test]
    fn the_fetch_shard_picks_a_live_leaf_with_a_committee() {
        let fix = Fixture::new();
        let host = fix.host(BlockHeight::GENESIS);
        let topology = host.process.topology_snapshot.load();
        assert!(
            topology.shard_trie().leaves().count() > 1,
            "the fixture's trie carries a leaf with no committee",
        );
        for spread in 0..4 {
            assert_eq!(
                host.beacon.fetch_shard(Some(ValidatorId::new(spread))),
                Some(SHARD),
            );
        }
    }

    /// Two hosts over a simulated network: this one, running `SHARD` with
    /// `committee[0]` seated, and a peer serving `SHARD` for `committee[1]`.
    struct Wire {
        network: SimulatedNetwork,
        streams: LinkStreams,
        peer: SimNetworkAdapter,
        now: Duration,
    }

    fn wired(fix: &Fixture, dispatch: SyncDispatch) -> (Wire, Host, Receiver<HostEvent>) {
        let validator_to_host = HashMap::from([
            (fix.committee.validator_id(0), 0),
            (fix.committee.validator_id(1), 1),
            (fix.committee.validator_id(2), 0),
            (fix.committee.validator_id(3), 0),
        ]);
        let network = SimulatedNetwork::new(
            NetworkConfig::default(),
            HostLayout {
                hosted: vec![BTreeSet::from([SHARD]); 2],
                validator_to_host,
            },
            7,
        );
        let (host, events) = fix.host_through_network(network.create_adapter(0), dispatch);
        let peer = network.create_adapter(1);
        let wire = Wire {
            network,
            streams: LinkStreams::new(7),
            peer,
            now: Duration::ZERO,
        };
        (wire, host, events)
    }

    impl Wire {
        /// Carry `host`'s requests to their answers and step everything
        /// they and the host's own continuations push, until quiet.
        fn pump(&mut self, host: &mut Host, events: &Receiver<HostEvent>) {
            loop {
                let requests = host.network().drain_pending_requests();
                let asked = !requests.is_empty();
                self.network
                    .accept_requests(0, self.now, requests, &mut self.streams);
                self.now += Duration::from_secs(1);
                self.network.flush_requests(self.now, &mut self.streams);
                let mut stepped = false;
                while let Ok(event) = events.try_recv() {
                    let _ = host.step(event);
                    stepped = true;
                }
                if !asked && !stepped {
                    return;
                }
            }
        }
    }

    fn add(host: &mut Host, fix: &Fixture, idx: usize) {
        let (validator, signer) = fix.identity(idx);
        host.add_participant(validator, signer);
        let _ = host.drain_pending_output();
    }

    /// A participant on the SPC committee asks for the proposals its
    /// dwell finds missing, and the beacon loop's fetch brings one back
    /// from a peer into its pool.
    #[test]
    fn a_participant_on_the_spc_committee_recovers_a_lost_proposal_through_the_host_fetch() {
        let fix = Fixture::new();
        let (mut wire, mut host, events) = wired(&fix, SyncDispatch::new());
        let author = fix.committee.validator_id(1);
        add(&mut host, &fix, 2);

        let network = NetworkDefinition::simulator();
        let signer = fix.committee.signer(1);
        let lost = Arc::new(Verifiable::from(
            BeaconProposalDraft::new(
                signer.as_ref(),
                &network,
                Epoch::new(1),
                BTreeMap::new(),
                Vec::new(),
                BTreeMap::new(),
                Vec::new(),
            )
            .and_then(BeaconProposalDraft::sign)
            .expect("the author's key signs its proposal"),
        ));
        wire.peer
            .register_request_handler(SHARD, move |request: GetBeaconProposalRequest| {
                GetBeaconProposalResponse::new(
                    (request.validator == author).then(|| Arc::clone(&lost)),
                )
            });

        let participant = attachment(&host, 2, &fix);
        let timer = |event| {
            HostEvent::Beacon(BeaconScopedInput::ParticipantTimer {
                participant,
                event: Box::new(event),
            })
        };
        let _ = host.step(timer(ProtocolEvent::BeaconCommitteeStartTimer));
        wire.pump(&mut host, &events);
        let pool = |host: &Host| {
            host.beacon
                .participant(fix.committee.validator_id(2))
                .expect("the participant runs")
                .proposal_pool()
                .get(author)
                .is_some()
        };
        assert!(
            !pool(&host),
            "the author's proposal never arrived by gossip"
        );

        let _ = host.step(timer(ProtocolEvent::BeaconSpcInputDwellTimer));
        wire.pump(&mut host, &events);
        assert!(
            pool(&host),
            "the dwell's fetch brings the lost proposal into the participant's pool",
        );
    }

    /// The catch-up sync asks the committee's other members even where
    /// this host serves the shard and holds an answer of its own.
    #[test]
    fn the_beacon_loops_block_sync_asks_past_the_host() {
        let fix = Fixture::new();
        let (mut wire, mut host, events) = wired(&fix, SyncDispatch::new());
        let counter = |count: &Arc<AtomicUsize>, block: Arc<Verified<CertifiedBeaconBlock>>| {
            let count = Arc::clone(count);
            move |_: GetBeaconBlockRequest| {
                count.fetch_add(1, Ordering::SeqCst);
                GetBeaconBlockResponse::found(Arc::new(Verifiable::from((*block).clone())))
            }
        };
        let here = Arc::new(AtomicUsize::new(0));
        let there = Arc::new(AtomicUsize::new(0));
        host.network()
            .register_request_handler(SHARD, counter(&here, fix.genesis_block()));
        wire.peer
            .register_request_handler(SHARD, counter(&there, fix.genesis_block()));

        host.beacon.start_sync(Epoch::new(1));
        wire.pump(&mut host, &events);
        assert_eq!(
            here.load(Ordering::SeqCst),
            0,
            "the host's own store is not asked"
        );
        assert_eq!(there.load(Ordering::SeqCst), 1);
    }

    /// Past epoch 0's boundary plus the skip timeout, so a ratify timer
    /// makes the tracker prevote the skip hash.
    fn past_the_skip_timeout() -> LocalTimestamp {
        LocalTimestamp::from_millis(3 * BeaconChainConfig::default().epoch_duration_ms)
    }

    /// A ratify timer handed back to `participant` as the outcome of its
    /// own dispatched work.
    fn ratify_timer(participant: Attachment) -> HostEvent {
        HostEvent::Beacon(BeaconScopedInput::Continuation {
            owner: BeaconOwner::Participant(participant),
            event: Box::new(ProtocolEvent::BeaconRatifyTimer),
        })
    }

    /// A signature a participant's dispatch queued before the participant
    /// left the host never leaves it: removal closes its release gate.
    #[test]
    fn a_removed_participants_queued_signature_never_leaves() {
        let fix = Fixture::new();
        let jobs = Arc::new(DeferredJobs::new(ProcessingTimes::disk(7), 7));
        let (_wire, mut host, _events) = wired(&fix, SyncDispatch::deferred(Arc::clone(&jobs)));
        let validator = fix.committee.validator_id(2);
        add(&mut host, &fix, 2);

        host.set_time(past_the_skip_timeout());
        let _ = host.step(ratify_timer(attachment(&host, 2, &fix)));
        let queued = jobs.take();
        assert!(!queued.is_empty(), "the skip prevote is queued on the pool");

        assert!(host.remove_participant(validator));
        for (_, job) in queued {
            job();
        }
        assert!(
            host.beacon_storage().ratify_record(validator).is_none(),
            "no ratify slot is spent, so no prevote was signed",
        );
    }

    /// An identity removed and added again is a new attachment: what the
    /// old one left in flight is dropped on arrival, and only the new
    /// one's own outcomes reach it.
    #[test]
    fn a_reattached_identity_never_sees_its_predecessors_continuation() {
        let fix = Fixture::new();
        let jobs = Arc::new(DeferredJobs::new(ProcessingTimes::disk(7), 7));
        let (_wire, mut host, _events) = wired(&fix, SyncDispatch::deferred(Arc::clone(&jobs)));
        let validator = fix.committee.validator_id(2);
        add(&mut host, &fix, 2);
        let predecessor = attachment(&host, 2, &fix);
        assert!(host.remove_participant(validator));
        add(&mut host, &fix, 2);
        let successor = attachment(&host, 2, &fix);
        assert_eq!(successor.validator, predecessor.validator);
        assert_ne!(successor, predecessor);

        host.set_time(past_the_skip_timeout());
        let _ = host.step(ratify_timer(predecessor));
        assert!(
            jobs.take().is_empty(),
            "the predecessor's continuation reaches nobody",
        );
        let _ = host.step(ratify_timer(successor));
        assert!(
            !jobs.take().is_empty(),
            "the successor's own continuation drives it",
        );
    }

    /// Dropping the loop, however it goes away, closes every
    /// participant's release gate.
    #[test]
    fn dropping_the_beacon_loop_closes_its_participants_gates() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        add(&mut host, &fix, 2);
        let gate = Arc::clone(&host.beacon.participants[&fix.committee.validator_id(2)].gate);
        assert!(gate.enter().is_some(), "a live participant's gate is open");
        drop(host);
        assert!(gate.enter().is_none(), "the dropped loop closed it");
    }

    /// A proposal ask goes to the committee of the author it prefers, as
    /// the fold places it; an author on no live shard with a committee
    /// falls back to the live-leaf rule.
    #[test]
    fn a_proposal_ask_goes_to_its_authors_shard() {
        let fix = Fixture::new();
        let id = |idx| fix.committee.validator_id(idx);
        let (left, right) = ShardId::ROOT.children();
        let topology = Arc::new(fix.topology(BTreeMap::from([
            (left, vec![id(0), id(1)]),
            (right, vec![id(2), id(3)]),
        ])));
        let spread_of = |host: &Host| {
            host.process.topology_snapshot.store(Arc::clone(&topology));
            host.beacon
                .fetch_shard(Some(id(2)))
                .expect("both leaves carry a committee")
        };
        let spread = spread_of(&fix.host(BlockHeight::GENESIS));
        let away = if spread == left { right } else { left };

        // The fold places `id(1)` on `away`; genesis leaves `id(3)` on the
        // root, which is no live leaf.
        let mut state = fix.genesis_state().clone();
        state
            .validators
            .get_mut(&id(1))
            .expect("a genesis validator")
            .status = ValidatorStatus::OnShard {
            shard: away,
            ready: true,
            placed_at_epoch: Epoch::GENESIS,
        };
        let mut host = fix.host_over_state(state);
        assert_eq!(spread_of(&host), spread);
        add(&mut host, &fix, 2);
        let _ = host.network().drain_pending_requests();

        let owner = BeaconOwner::Participant(attachment(&host, 2, &fix));
        let mut routed = |author: ValidatorId| {
            host.beacon.process_action(
                owner,
                Action::Fetch(FetchRequest::Ask {
                    ids: proposals(&[(Epoch::new(1), author)]),
                    shard: ShardId::ROOT,
                    preferred: Some(author),
                    class: None,
                }),
            );
            let requests = host.network().drain_pending_requests();
            assert_eq!(requests.len(), 1);
            requests[0].shard
        };
        assert_eq!(routed(id(1)), away, "the author's committee is asked");
        assert_eq!(
            routed(id(3)),
            spread,
            "an author on no live shard falls back to the live-leaf rule",
        );
    }

    /// The certified header of an empty `shard` block at `height`, its
    /// parent's certificate dated `anchor_ms`.
    fn header_at(
        shard: ShardId,
        height: u64,
        anchor_ms: u64,
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        let block = make_live_block(
            shard,
            BlockHeight::new(height),
            anchor_ms,
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        let certified =
            Verified::<CertifiedBlock>::new_unchecked_for_test(certify(block, anchor_ms));
        Arc::new(certified.certified_header())
    }

    fn report(host: &mut Host, chain: ChainRegistration, input: BeaconInput) {
        let _ = host.step(HostEvent::Beacon(BeaconScopedInput::Shard { chain, input }));
    }

    /// A commit reported twice shifts the chain's anchors once: the fold
    /// shifts them once per committed height, so the committee anchor
    /// stays one hop behind the tip.
    #[test]
    fn a_commit_reported_twice_keeps_the_fold_anchors_one_hop_apart() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        let chain = loop_of(&mut host).chain;
        let anchors = |host: &Host| host.beacon.fold().chain(chain).expect("registered").anchors;
        let before = anchors(&host).block;
        for (height, anchor_ms) in [(1, 10_000), (2, 20_000)] {
            let header = header_at(SHARD, height, anchor_ms);
            for _ in 0..2 {
                report(
                    &mut host,
                    chain,
                    BeaconInput::LocalCommit {
                        header: Arc::clone(&header),
                    },
                );
            }
        }
        let after = anchors(&host);
        assert_eq!(after.block, WeightedTimestamp::from_millis(20_000));
        assert_eq!(
            after.committee,
            WeightedTimestamp::from_millis(10_000),
            "the committee anchor trails the tip by exactly one commit",
        );
        assert_ne!(before, after.committee);
    }

    /// A certified header reported twice is held once, as the copy first
    /// held.
    #[test]
    fn a_certified_header_reported_twice_is_recorded_once() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        let chain = loop_of(&mut host).chain;
        let first = header_at(SHARD, 1, 10_000);
        let second = Arc::new((*first).clone());
        for header in [Arc::clone(&first), second] {
            report(&mut host, chain, BeaconInput::CertifiedHeader { header });
        }
        let held = host
            .beacon
            .fold()
            .shard_source()
            .header(SHARD, BlockHeight::new(1))
            .expect("the certified header is recorded");
        assert!(
            Arc::ptr_eq(held, &first),
            "a header reported twice keeps the copy first held",
        );
    }

    /// Two participants on one host: each signs its own beacon duty, under
    /// its own key and into its own durable record.
    #[test]
    fn two_identities_on_one_host_each_sign_their_own_spc_view() {
        let fix = Fixture::new();
        let (mut wire, mut host, events) = wired(&fix, SyncDispatch::new());
        add(&mut host, &fix, 2);
        add(&mut host, &fix, 3);
        for idx in [2, 3] {
            let participant = attachment(&host, idx, &fix);
            let _ = host.step(HostEvent::Beacon(BeaconScopedInput::ParticipantTimer {
                participant,
                event: Box::new(ProtocolEvent::BeaconCommitteeStartTimer),
            }));
        }
        wire.pump(&mut host, &events);
        for idx in [2, 3] {
            let validator = fix.committee.validator_id(idx);
            assert!(
                host.beacon_storage()
                    .beacon_vote_record(validator)
                    .is_some(),
                "validator {idx} signed its own SPC duty",
            );
            assert!(
                host.beacon
                    .participant(validator)
                    .expect("the participant runs")
                    .proposal_pool()
                    .get(validator)
                    .is_some(),
                "validator {idx} pooled its own proposal",
            );
        }
    }

    /// Commit a skip block for every epoch in `1..=tip` over the genesis
    /// state, each state's live boundary at its own epoch, so the fold a
    /// host resumes over them retains only the windows at its tip.
    fn advanced_history(
        fix: &Fixture,
        tip: u64,
    ) -> Vec<(Arc<Verified<CertifiedBeaconBlock>>, BeaconState)> {
        let mut history = vec![(fix.genesis_block(), fix.genesis_state().clone())];
        for epoch in 1..=tip {
            let (parent, state) = history.last().expect("genesis is first").clone();
            let mut state = state;
            state.current_epoch = Epoch::new(epoch);
            for boundary in state.boundaries.values_mut() {
                boundary.last_live_epoch = Epoch::new(epoch);
            }
            history.push((skip_block(&parent, Epoch::new(epoch)), state));
        }
        history
    }

    /// A ratified skip for `epoch` over `parent`.
    fn skip_block(
        parent: &Verified<CertifiedBeaconBlock>,
        epoch: Epoch,
    ) -> Arc<Verified<CertifiedBeaconBlock>> {
        let tip = parent.block_hash();
        let block = BeaconBlock::skip(epoch, tip);
        let cert = RatifyCert::new(
            tip,
            epoch,
            RatifyRound::INITIAL,
            block.block_hash(),
            SignerBitfield::new(4),
            AggregateSignature::new([0; 96]),
        );
        Arc::new(Verified::new_unchecked_for_test(
            CertifiedBeaconBlock::new_unchecked(block, BeaconCert::Skip(cert)),
        ))
    }

    /// A chain anchored below the oldest window the fold retains widens
    /// the schedule at registration, so the reply resolves the committee
    /// its tip anchors on.
    #[test]
    fn a_shard_registered_below_the_fold_floor_resolves_its_tip_committee() {
        let fix = Fixture::new();
        let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 8), far_future());
        let anchor = in_epoch(&fix, 2);
        assert!(
            host.beacon.fold().schedule().at(anchor).is_none(),
            "the fold resumed past the anchor's window",
        );
        let (sender, _receiver) = unbounded();
        let registration = host.beacon.register(
            SHARD,
            LocalChainAnchors {
                committee: anchor,
                block: anchor,
            },
            BlockHeight::new(5),
            sender,
        );
        assert!(
            registration.schedule.at(anchor).is_some(),
            "the registration widened the schedule back to the anchor",
        );
    }

    /// A shard a host joins at runtime builds its replica from the
    /// registration's reply: the widened schedule, not the process's.
    #[test]
    fn a_runtime_join_builds_its_replica_from_the_registration_reply() {
        let fix = Fixture::new();
        let (mut host, events) = fix.host_over_history(advanced_history(&fix, 8), far_future());
        let anchor = in_epoch(&fix, 2);
        let recovered = RecoveredState {
            committed_height: BlockHeight::new(5),
            committed_block_anchor_wt: Some(anchor),
            committed_committee_anchor_wt: Some(anchor),
            ..RecoveredState::default()
        };
        let (sender, _receiver) = unbounded();
        host.add_shard(
            &fix.replica_config(),
            HostedChain {
                shard: SHARD,
                storage: SimShardStorage::new(shard_prefix_path(SHARD)),
                recovered: &recovered,
                signers: vec![fix.identity(0)],
            },
            sender,
        );
        drop(events);
        let replica = host.replica(SHARD);
        assert!(
            replica.schedule().at(anchor).is_some(),
            "the replica resolves its tip's committee from its first schedule",
        );
        assert_eq!(replica.schedule_epoch(), Epoch::new(8));
    }

    /// A host restarted from its stores holds the schedule the next
    /// beacon block folds once the beacon loop hands it over, and not
    /// before.
    #[test]
    fn a_restarted_host_installs_the_next_beacon_blocks_schedule() {
        let fix = Fixture::new();
        let history = advanced_history(&fix, 2);
        let tip = Arc::clone(&history.last().expect("a tip").0);
        let storage = SimShardStorage::new(shard_prefix_path(SHARD));
        commit_one(&storage, 1);
        let (mut host, events) = fix.host_resumed(history, storage, far_future());
        let replica_epoch = |host: &Host| host.replica(SHARD).schedule_epoch();
        assert_eq!(replica_epoch(&host), Epoch::new(2));

        let _ = host.step(fold_outcome(ProtocolEvent::BeaconBlockVerified {
            result: Ok(skip_block(&tip, Epoch::new(3))),
        }));
        assert_eq!(host.beacon.fold().state().current_epoch, Epoch::new(3));
        assert_eq!(
            replica_epoch(&host),
            Epoch::new(2),
            "the schedule reaches the replica as an event of its own",
        );
        for event in events.try_iter() {
            let _ = host.step(event);
        }
        assert_eq!(replica_epoch(&host), Epoch::new(3));
    }

    /// A block that reaches the loop again — a second verified copy off
    /// gossip, then a sync delivery of it — is written to beacon storage
    /// once, by the fold's one adoption.
    #[test]
    fn the_fold_commits_each_beacon_block_once() {
        let fix = Fixture::new();
        let (mut host, events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
        let block = skip_block(&fix.genesis_block(), Epoch::new(1));
        let verified = || {
            fold_outcome(ProtocolEvent::BeaconBlockVerified {
                result: Ok(Arc::clone(&block)),
            })
        };
        let (ran, left) = crash_point::armed(Some(u64::MAX), || {
            let _ = host.step(verified());
            let _ = host.step(verified());
            host.beacon.on_sync_response(
                Epoch::new(1),
                Some(Arc::new(Verifiable::from((*block).clone()))),
            );
            for event in events.try_iter() {
                let _ = host.step(event);
            }
        });
        assert!(ran.is_ok());
        assert_eq!(host.beacon.fold().state().current_epoch, Epoch::new(1));
        assert_eq!(
            left,
            Some(u64::MAX - 1),
            "one storage write across every copy of the block",
        );
        assert_eq!(
            host.beacon_storage().latest_committed_epoch(),
            Some(Epoch::new(1)),
            "the one write is the block's commit",
        );
    }

    /// A host restarted over beacon storage whose tip is epoch 8 syncs
    /// from 9: its catch-up starts at the storage tip, with nothing
    /// committed in this run.
    #[test]
    fn beacon_sync_resumes_from_the_storage_tip_after_a_restart() {
        let fix = Fixture::new();
        let (mut host, _events) = fix.host_resumed(
            advanced_history(&fix, 8),
            SimShardStorage::new(shard_prefix_path(SHARD)),
            far_future(),
        );
        host.beacon.start_sync(Epoch::new(10));
        let status = host.beacon.beacon_block.status(&());
        assert_eq!(status.current_height, 8, "the watermark is the storage tip");
        assert_eq!(status.blocks_behind, 2);
        assert_eq!(
            beacon_blocks_asked(&host),
            vec![Epoch::new(9)],
            "one epoch in flight, the one above the tip",
        );
    }

    /// A sync started while no live leaf has a committee to ask holds its
    /// epoch behind the backoff rather than in flight, so once a committee
    /// appears the next tick asks it.
    #[test]
    fn a_beacon_sync_with_no_committee_to_ask_retries_once_one_appears() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        let live = host.process.topology_snapshot.load_full();
        host.process
            .topology_snapshot
            .store(Arc::new(fix.topology(BTreeMap::new())));

        host.beacon.start_sync(Epoch::new(1));
        assert!(beacon_blocks_asked(&host).is_empty(), "no committee to ask");

        host.process.topology_snapshot.store(live);
        let later = host.beacon.now.plus(Duration::from_secs(60));
        host.set_time(later);
        let _ = host.step(HostEvent::beacon_fetch_tick());
        assert_eq!(
            beacon_blocks_asked(&host),
            vec![Epoch::new(1)],
            "the tick asks the committee"
        );
    }

    /// The epochs of the beacon blocks `host` has asked for since the
    /// last call.
    fn beacon_blocks_asked(host: &Host) -> Vec<Epoch> {
        let mut asked = Vec::new();
        for pending in host.network().drain_pending_requests() {
            if let Some(request) = pending.request::<GetBeaconBlockRequest>() {
                asked.push(request.epoch);
            }
        }
        asked
    }

    /// The beacon loop's fold hands back `event` as its own outcome.
    fn fold_outcome(event: ProtocolEvent) -> HostEvent {
        HostEvent::Beacon(BeaconScopedInput::Continuation {
            owner: BeaconOwner::Fold,
            event: Box::new(event),
        })
    }

    /// An adoption that lands after a chain registers and before its loop
    /// runs reaches the loop's channel, so the loop's first event is the
    /// schedule it would otherwise miss.
    #[test]
    fn an_adoption_between_register_and_spawn_reaches_the_new_loop() {
        let fix = Fixture::new();
        let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
        let (sender, receiver) = unbounded();
        let _ = host.beacon.register(
            SHARD,
            LocalChainAnchors::GENESIS,
            BlockHeight::GENESIS,
            sender,
        );
        let _ = host.step(fold_outcome(ProtocolEvent::BeaconBlockVerified {
            result: Ok(skip_block(&fix.genesis_block(), Epoch::new(1))),
        }));
        let persisted: Vec<Epoch> = receiver
            .try_iter()
            .filter_map(|event| match event {
                HostEvent::Shard(shard, ShardScopedInput::Protocol(event)) if shard == SHARD => {
                    match *event {
                        ProtocolEvent::BeaconBlockPersisted { epoch, .. } => Some(epoch),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect();
        assert_eq!(persisted, vec![Epoch::new(1)]);
    }

    /// Three registered chains on three shards, each with its own channel.
    fn three_chains(host: &mut Host) -> Vec<(ChainRegistration, ShardId, Receiver<HostEvent>)> {
        [0, 1, 2]
            .into_iter()
            .map(|path| ShardId::leaf(2, path))
            .map(|shard| {
                let (sender, receiver) = unbounded();
                let registration = host.beacon.register(
                    shard,
                    LocalChainAnchors::GENESIS,
                    BlockHeight::GENESIS,
                    sender,
                );
                (registration.token, shard, receiver)
            })
            .collect()
    }

    /// The commit-proof asks each channel received, as `(source, height)`.
    fn asks(receiver: &Receiver<HostEvent>) -> Vec<(ShardId, BlockHeight)> {
        receiver
            .try_iter()
            .filter_map(|event| match event {
                HostEvent::Shard(_, ShardScopedInput::Protocol(event)) => match *event {
                    ProtocolEvent::CommitProofNeeded {
                        source_shard,
                        block_height,
                    } => Some((source_shard, block_height)),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    fn ask_proof(host: &mut Host, source: ShardId, height: BlockHeight) {
        host.beacon.process_action(
            participant(2),
            Action::Continuation(ProtocolEvent::CommitProofNeeded {
                source_shard: source,
                block_height: height,
            }),
        );
    }

    /// A participant's ask for a hosted shard's commit proof goes to a
    /// sibling loop: a loop never answers for its own shard.
    #[test]
    fn a_boundary_ask_for_a_hosted_shard_is_answered_by_a_sibling_loop() {
        let fix = Fixture::new();
        let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
        let chains = three_chains(&mut host);
        let (_, own, own_rx) = &chains[0];
        ask_proof(&mut host, *own, BlockHeight::new(4));
        assert!(
            asks(own_rx).is_empty(),
            "a loop never answers for its own shard"
        );
        assert_eq!(asks(&chains[1].2), vec![(*own, BlockHeight::new(4))]);
        assert!(asks(&chains[2].2).is_empty(), "the ask goes to one loop");
    }

    /// The loop an ask went to deregistering hands the ask to the next
    /// eligible loop; one that answered is not asked again.
    #[test]
    fn a_boundary_ask_survives_its_loops_deregister() {
        let fix = Fixture::new();
        let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
        let chains = three_chains(&mut host);
        let source = chains[0].1;
        ask_proof(&mut host, source, BlockHeight::new(4));
        ask_proof(&mut host, source, BlockHeight::new(5));
        assert_eq!(asks(&chains[1].2).len(), 2);
        let proven = header_at(source, 5, 10_000);
        report(
            &mut host,
            chains[1].0,
            BeaconInput::CommitProven { header: proven },
        );

        host.beacon.deregister(chains[1].0);
        assert_eq!(
            asks(&chains[2].2),
            vec![(source, BlockHeight::new(4))],
            "the unanswered ask moves to the next loop",
        );
    }

    /// An ask no participant holds past the next adoption loses its
    /// route: the loop it went to deregistering hands it to no one.
    #[test]
    fn an_unanswered_asks_route_is_dropped_at_the_next_adoption() {
        let fix = Fixture::new();
        let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
        let chains = three_chains(&mut host);
        let source = chains[0].1;
        ask_proof(&mut host, source, BlockHeight::new(4));
        assert_eq!(asks(&chains[1].2).len(), 1);
        let _ = host.step(fold_outcome(ProtocolEvent::BeaconBlockVerified {
            result: Ok(skip_block(&fix.genesis_block(), Epoch::new(1))),
        }));
        assert_eq!(host.beacon.fold().state().current_epoch, Epoch::new(1));

        host.beacon.deregister(chains[1].0);
        assert!(
            asks(&chains[2].2).is_empty(),
            "an ask the adoption retired is not handed on",
        );
    }

    /// A deregistered loop's late reports change nothing: a commit proof
    /// it reports leaves the route another loop holds for the same ask,
    /// and a source header it reports is not recorded.
    #[test]
    fn a_deregistered_loops_late_reports_change_nothing() {
        let fix = Fixture::new();
        let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
        let chains = three_chains(&mut host);
        let source = chains[0].1;
        let stale = chains[1].0;
        host.beacon.deregister(stale);
        ask_proof(&mut host, source, BlockHeight::new(4));
        assert_eq!(asks(&chains[2].2), vec![(source, BlockHeight::new(4))]);
        let (sender, rebuilt) = unbounded();
        let _ = host.beacon.register(
            chains[1].1,
            LocalChainAnchors::GENESIS,
            BlockHeight::GENESIS,
            sender,
        );

        report(
            &mut host,
            stale,
            BeaconInput::CommitProven {
                header: header_at(source, 4, 10_000),
            },
        );
        report(
            &mut host,
            stale,
            BeaconInput::SourceHeader {
                header: header_at(source, 5, 10_000),
            },
        );
        assert!(
            host.beacon
                .fold()
                .shard_source()
                .header(source, BlockHeight::new(5))
                .is_none(),
            "a closed loop's source header is not recorded",
        );
        host.beacon.deregister(chains[2].0);
        assert_eq!(
            asks(&rebuilt),
            vec![(source, BlockHeight::new(4))],
            "the ask's route outlived the closed loop's proof",
        );
    }

    /// The certified header of `shard`'s block at `height` over the block
    /// `parent`, its parent's certificate dated `parent_ms`, committing
    /// `leaf_count` witness leaves.
    fn linked_header(
        shard: ShardId,
        height: u64,
        parent: BlockHash,
        parent_ms: u64,
        leaf_count: u64,
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        let qc = |block, height, parent| {
            QuorumCertificate::new(
                block,
                shard,
                BlockHeight::new(height),
                parent,
                Round::INITIAL,
                SignerBitfield::new(4),
                AggregateSignature::ZERO,
                WeightedTimestamp::from_millis(parent_ms),
            )
        };
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height: BlockHeight::new(height),
            parent_block_hash: parent,
            parent_qc: qc(parent, height.saturating_sub(1), BlockHash::ZERO).into(),
            round: Round::new(height),
            beacon_witness_root: BeaconWitnessRoot::from_raw(Hash::from_bytes(
                format!("bw-{height}").as_bytes(),
            )),
            beacon_witness_leaf_count: BeaconWitnessLeafCount::new(leaf_count),
            ..Default::default()
        });
        let certificate = qc(header.hash(), height, parent);
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header,
            certificate,
        )))
    }

    /// Adding the host's first participant on the beacon committee raises
    /// the fold's committee flag, which fetches the witness chunk of a
    /// crossing the fold already holds; removing it lowers the flag and
    /// abandons the fetch.
    #[test]
    fn a_committee_participant_coming_and_going_starts_and_abandons_witness_fetches() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        let chain = loop_of(&mut host).chain;
        let source = ShardId::ROOT;
        let b = linked_header(source, 5, BlockHash::ZERO, 1, 3);
        let c = linked_header(source, 6, b.block_hash(), 300_001, 3);
        let d = linked_header(source, 7, c.block_hash(), 300_001, 3);
        for header in [b, c, d] {
            report(&mut host, chain, BeaconInput::SourceHeader { header });
        }
        assert!(
            host.beacon.interest.witnesses.is_empty(),
            "off the committee the fold asks for no witness",
        );

        add(&mut host, &fix, 0);
        assert!(
            host.beacon
                .interest
                .witnesses
                .keys()
                .any(|run| run.0 == source),
            "the first committee participant starts the held crossing's fetch",
        );

        assert!(host.remove_participant(fix.committee.validator_id(0)));
        assert!(
            host.beacon.interest.witnesses.is_empty(),
            "the last committee participant leaving abandons it",
        );
    }

    /// The loop holds a commit proof one participant asked for and hands
    /// that participant's awaiting proposal to its pool.
    #[test]
    #[allow(clippy::too_many_lines)] // one certified chain built and walked end to end
    fn a_commit_proof_one_participant_asked_for_releases_its_proposal_on_the_loop() {
        let fix = Fixture::new();
        let (mut host, _events) =
            fix.host_over_history(advanced_history(&fix, 0), LocalTimestamp::ZERO);
        let shard = ShardId::ROOT;
        let (sender, _receiver) = unbounded();
        let chain = host
            .beacon
            .register(
                shard,
                LocalChainAnchors::GENESIS,
                BlockHeight::GENESIS,
                sender,
            )
            .token;
        add(&mut host, &fix, 0);
        let me = fix.committee.validator_id(0);
        let from = fix.committee.validator_id(1);
        let cut = fix.genesis_state().chain_config.epoch_duration_ms;
        let network = NetworkDefinition::simulator();

        let header = |height: u64, parent_qc: &QuorumCertificate| {
            BlockHeader::new(BlockHeaderParts {
                shard_id: shard,
                height: BlockHeight::new(height),
                parent_block_hash: parent_qc.block_hash(),
                parent_qc: parent_qc.clone().into(),
                round: Round::new(height),
                beacon_witness_root: BeaconWitnessRoot::from_raw(Hash::from_bytes(b"bw")),
                beacon_witness_leaf_count: BeaconWitnessLeafCount::new(3),
                ..Default::default()
            })
        };
        let qc_over = |header: &BlockHeader, wt: u64| {
            let votes: Vec<(usize, Verified<BlockVote>)> = (0..3)
                .map(|seat| {
                    let vote = BlockVote::new(
                        &network,
                        header.hash(),
                        header.parent_block_hash(),
                        shard,
                        header.height(),
                        header.round(),
                        fix.committee.validator_id(seat),
                        fix.committee.signer(seat).as_ref(),
                        ProposerTimestamp::from_millis(wt),
                    )
                    .expect("vote signs");
                    (seat, Verified::new_unchecked_for_test(vote))
                })
                .collect();
            Verified::<QuorumCertificate>::from_verified_votes(
                &BlsVerifier,
                header.hash(),
                shard,
                header.height(),
                header.round(),
                header.parent_block_hash(),
                header.parent_qc().weighted_timestamp(),
                &votes,
            )
            .expect("aggregates over a quorum")
            .into_inner()
        };
        let certified = |header: &BlockHeader, qc: &QuorumCertificate| {
            Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
                header.clone(),
                qc.clone(),
            )))
        };

        // `b` anchors short of the cut and is certified past it; `c`
        // embeds that certificate and `d` commits `c`.
        let below = QuorumCertificate::new(
            BlockHash::ZERO,
            shard,
            BlockHeight::new(3),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(cut - 2),
        );
        let a = header(4, &below);
        let a_qc = qc_over(&a, cut - 1);
        let b = header(5, &a_qc);
        let b_qc = qc_over(&b, cut + 1);
        let c = header(6, &b_qc);
        let c_qc = qc_over(&c, cut + 2);
        let d = header(7, &c_qc);
        let d_qc = qc_over(&d, cut + 3);

        let proposal = Verified::new_unchecked_for_test(BeaconProposal::new(
            std::iter::once((shard, Some(b_qc.clone()))).collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        ));
        report(
            &mut host,
            chain,
            BeaconInput::CertifiedHeader {
                header: certified(&a, &a_qc),
            },
        );
        let _ = host.step(HostEvent::Beacon(BeaconScopedInput::Protocol(Box::new(
            ProtocolEvent::BeaconProposalReceived {
                from,
                epoch: Epoch::GENESIS.next(),
                proposal: Arc::new(Verifiable::from(proposal)),
            },
        ))));
        for (header, qc) in [(&b, &b_qc), (&c, &c_qc)] {
            report(
                &mut host,
                chain,
                BeaconInput::CertifiedHeader {
                    header: certified(header, qc),
                },
            );
        }
        assert!(
            host.beacon
                .participant(me)
                .expect("runs")
                .proposal_pool()
                .get(from)
                .is_none(),
            "the boundary's dating child is only certified, so the proposal awaits",
        );
        let asked: Vec<_> = [(&b, &b_qc), (&c, &c_qc), (&d, &d_qc)]
            .into_iter()
            .filter(|(header, _)| {
                host.beacon
                    .participant(me)
                    .expect("runs")
                    .asked(shard, header.height())
            })
            .collect();
        assert!(!asked.is_empty(), "the awaiting proposal asks for a proof");

        for (header, qc) in asked {
            report(
                &mut host,
                chain,
                BeaconInput::CommitProven {
                    header: certified(header, qc),
                },
            );
        }
        assert!(
            host.beacon
                .participant(me)
                .expect("runs")
                .proposal_pool()
                .get(from)
                .is_some(),
            "the proven commit releases the asker's proposal into its pool",
        );
    }

    /// The states a merge into the root leaves: window 1 runs the root's
    /// two children and window 2 the root alone, so each child's terminal
    /// window is 1.
    fn merged_history(fix: &Fixture) -> Vec<(Arc<Verified<CertifiedBeaconBlock>>, BeaconState)> {
        let genesis = fix.genesis_state();
        let mut split = genesis.clone();
        split.current_epoch = Epoch::new(1);
        let committee = split
            .shard_committees
            .remove(&ShardId::ROOT)
            .expect("genesis seats the root");
        let (left, right) = ShardId::ROOT.children();
        split.shard_committees = BTreeMap::from([(left, committee.clone()), (right, committee)]);
        split.next_shard_committees = split.shard_committees.clone();
        split.shard_consensus_members = split.ready_consensus_members(&split.shard_committees);
        let mut merged = genesis.clone();
        merged.current_epoch = Epoch::new(2);
        for boundary in merged.boundaries.values_mut() {
            boundary.last_live_epoch = Epoch::new(2);
        }
        let first = skip_block(&fix.genesis_block(), Epoch::new(1));
        let tip = skip_block(&first, Epoch::new(2));
        vec![
            (fix.genesis_block(), genesis.clone()),
            (first, split),
            (tip, merged),
        ]
    }

    /// A chain that committed past its terminal answers no commit-proof
    /// ask: the ask goes to a live chain registered after it.
    #[test]
    fn a_boundary_ask_skips_a_chain_past_its_terminal() {
        let fix = Fixture::new();
        let (mut host, _events) = fix.host_over_history(merged_history(&fix), far_future());
        let (left, right) = ShardId::ROOT.children();
        let (terminated_tx, terminated_rx) = unbounded();
        let terminated = host
            .beacon
            .register(
                left,
                LocalChainAnchors {
                    committee: in_epoch(&fix, 1),
                    block: in_epoch(&fix, 2),
                },
                BlockHeight::new(4),
                terminated_tx,
            )
            .token;
        assert!(
            host.beacon
                .fold()
                .chain(terminated)
                .is_some_and(|chain| chain.terminal_committed),
            "the chain registers past its terminal",
        );
        let (live_tx, live_rx) = unbounded();
        let _ = host.beacon.register(
            ShardId::ROOT,
            LocalChainAnchors {
                committee: in_epoch(&fix, 2),
                block: in_epoch(&fix, 2),
            },
            BlockHeight::new(4),
            live_tx,
        );
        ask_proof(&mut host, right, BlockHeight::new(4));
        assert!(asks(&terminated_rx).is_empty());
        assert_eq!(asks(&live_rx), vec![(right, BlockHeight::new(4))]);
    }

    /// A shard loop on a thread of its own releases its chain's
    /// registration as a panic unwinds the thread.
    #[test]
    fn a_panicking_shard_thread_deregisters_its_chain() {
        let fix = Fixture::new();
        let (host, events) = fix.host_with_events(BlockHeight::GENESIS);
        let (_process, mut shards, mut beacon) = host.into_parts();
        let shard_loop = shards.remove(&SHARD).expect("the fixture hosts SHARD");
        let chain = shard_loop.chain;
        let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _shard_loop = ThreadShardLoop::from(shard_loop);
            panic!("the shard loop dies");
        }));
        assert!(died.is_err());
        assert!(beacon.fold().chain(chain).is_some());
        for event in events.try_iter() {
            if let HostEvent::Beacon(input) = event {
                let _ = beacon.run_step(input);
            }
        }
        assert!(
            beacon.fold().chain(chain).is_none(),
            "the unwind deregistered the chain",
        );
    }

    /// A rebuilt chain registers again before its old loop deregisters;
    /// the old loop's deregister and any commit it reports late touch
    /// nothing of the new entry.
    #[test]
    fn a_rebuilt_loops_registration_survives_the_old_loops_deregister_and_late_commits() {
        let fix = Fixture::new();
        let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
        let register = |host: &mut Host, height| {
            let (sender, _receiver) = unbounded();
            host.beacon
                .register(
                    SHARD,
                    LocalChainAnchors::GENESIS,
                    BlockHeight::new(height),
                    sender,
                )
                .token
        };
        let old = register(&mut host, 3);
        let new = register(&mut host, 5);
        host.beacon.deregister(old);
        report(
            &mut host,
            old,
            BeaconInput::LocalCommit {
                header: header_at(SHARD, 6, 10_000),
            },
        );
        let chain = *host.beacon.fold().chain(new).expect("the new entry stands");
        assert_eq!(chain.height, BlockHeight::new(5));
        assert_eq!(chain.anchors, LocalChainAnchors::GENESIS);
        assert!(host.beacon.fold().chain(old).is_none());
    }

    /// Attaching a validator to another of its host's shards and leaving
    /// the first touches neither its participant nor its attachment.
    #[test]
    fn a_seat_moving_between_shards_keeps_its_participant() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        add(&mut host, &fix, 0);
        let before = attachment(&host, 0, &fix);
        let other = ShardId::leaf(1, 1);
        let (sender, _receiver) = unbounded();
        host.add_shard(
            &fix.replica_config(),
            HostedChain {
                shard: other,
                storage: SimShardStorage::new(shard_prefix_path(other)),
                recovered: &RecoveredState::default(),
                signers: vec![fix.identity(0)],
            },
            sender,
        );
        assert!(host.remove_shard(SHARD).is_some());
        assert_eq!(attachment(&host, 0, &fix), before);
        assert!(
            host.beacon.participants[&fix.committee.validator_id(0)]
                .gate
                .enter()
                .is_some(),
            "its release gate stays open",
        );
    }

    /// Far enough past genesis that no beacon history is too young for
    /// the retention horizon to keep.
    fn far_future() -> LocalTimestamp {
        LocalTimestamp::from_millis(1 << 50)
    }

    /// A weighted timestamp inside `epoch`'s window.
    fn in_epoch(fix: &Fixture, epoch: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(
            epoch * fix.genesis_state().chain_config.epoch_duration_ms + 1,
        )
    }

    /// The beacon loop is the one writer of the process's topology, and
    /// what it publishes releases the submissions parked while the host
    /// seats a reshape successor: they route again against it.
    #[test]
    fn an_adoption_on_the_beacon_loop_releases_a_parked_submission() {
        let fix = Fixture::new();
        let (mut host, events) = fix.host_with_events(BlockHeight::GENESIS);
        let id = |idx| fix.committee.validator_id(idx);
        let seating = fix.topology_of(
            4,
            (0..4)
                .map(|path| {
                    (
                        ShardId::leaf(2, path),
                        vec![id(usize::try_from(path).expect("small"))],
                    )
                })
                .collect(),
        );
        assert!(seating.reshape_handoff_pending(SHARD));
        host.process.topology_snapshot.store(Arc::new(seating));
        let tx = Arc::new(test_transaction(1));
        assert!(host.process.submit_transaction(&tx));
        let routed = |events: &Receiver<HostEvent>| {
            events.try_iter().find_map(|event| match event {
                HostEvent::Shard(
                    shard,
                    ShardScopedInput::AdmitAndGossipTransaction { tx: held, .. },
                ) if held.hash() == tx.hash() => Some(shard),
                _ => None,
            })
        };
        assert_eq!(
            routed(&events),
            None,
            "the submission waits for the successor"
        );

        let live = fix.topology(BTreeMap::from([(SHARD, vec![id(0), id(1)])]));
        let (folded, held) = host.process.folded_schedule();
        let (_, newest) = held.retained_epochs().expect("the host holds a schedule");
        let epoch = folded.next();
        host.beacon.process_action(
            BeaconOwner::Fold,
            Action::TopologyChanged {
                epoch,
                schedule: Arc::new(TopologySchedule::new(
                    fix.genesis_state().chain_config.epoch_duration_ms,
                    newest.next(),
                    Arc::new(live),
                )),
            },
        );
        assert_eq!(
            routed(&events),
            Some(SHARD),
            "the published topology releases the submission to the shard it routes to",
        );
    }
}
