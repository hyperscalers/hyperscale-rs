//! The validator identities the beacon loop runs a participant for, and
//! the actions each dispatches.

use std::sync::Arc;

use hyperscale_beacon::action_handlers::handle_action as handle_beacon_action;
use hyperscale_beacon::verification::RatifyVoteSlotKey;
use hyperscale_beacon::{BeaconFold, BeaconParticipant, ParticipantStep};
use hyperscale_core::{Action, ActionOwner, BeaconActionContext, Gate, ProtocolEvent};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{
    BeaconBlockHash, BeaconProposal, CandidateBeaconBlock, Epoch, Signer, ValidatorId, Verifiable,
    Verified,
};
use tracing::warn;

use super::BeaconLoop;
use crate::beacon::{BeaconCandidateBinding, BeaconProposalBinding};
use crate::event::{Attachment, BeaconOwner, BeaconScopedInput, HostEvent};
use crate::shard::{StepOutput, TimerOp, TimerOwner};

impl<S, N, D> BeaconLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
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
    pub(super) fn validator_list(&self) -> Vec<ValidatorId> {
        self.validators().collect()
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

    /// Run a participant handler, adopting the block it certified.
    pub(super) fn drive<T: Into<ParticipantStep>>(
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

    /// Set the fold's committee flag to whether any participant sits on
    /// the beacon committee.
    pub(super) fn refresh_committee_flag(&mut self) {
        let on = self
            .participants
            .values()
            .any(|p| p.duty.is_on_committee(&self.fold));
        let actions = self.fold.set_host_on_committee(on);
        self.run_fold_actions(actions);
    }

    /// The verified proposal a received or fetched one carries. The wire
    /// handler and the fetch's response boundary check a peer's VRF
    /// reveal before handing it over, and the host's own sign and send
    /// seal it, so every proposal reaching the loop keeps its marker; one
    /// that does not is dropped with a warning.
    pub(super) fn sealed(
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

    /// Handle the actions `validator`'s participant emitted: the effects
    /// any owner's actions have, its timers, and its delegated actions on
    /// the dispatch pool.
    fn run_participant_actions(&mut self, validator: ValidatorId, actions: Vec<Action>) {
        let Some(participant) = self.participants.get(&validator) else {
            return;
        };
        let attachment = participant.attachment;
        self.actions_generated += actions.len();
        for action in actions {
            if let Some(action) =
                self.process_shared_action(BeaconOwner::Participant(attachment), action)
            {
                self.process_participant_action(attachment, action);
            }
        }
    }

    /// Handle one of a participant's own actions: a timer it arms or
    /// cancels, or a beacon-owned action run on the dispatch pool.
    fn process_participant_action(&mut self, attachment: Attachment, action: Action) {
        let owner = TimerOwner::Participant(attachment);
        match action {
            Action::SetTimer { id, duration } => {
                self.pending_timer_ops.push(TimerOp::Set {
                    owner,
                    id,
                    duration,
                });
            }
            Action::CancelTimer { id } => {
                self.pending_timer_ops.push(TimerOp::Cancel { owner, id });
            }
            other if other.owner() == ActionOwner::Beacon => {
                if !self.joins_a_shared_check(attachment, &other) {
                    self.dispatch_participant_action(attachment.validator, other);
                }
            }
            other => warn!(
                action = other.type_name(),
                "BeaconLoop: unexpected participant action — dropping"
            ),
        }
    }

    /// Whether `action` is a check another participant already runs, which
    /// `attachment` now waits on too. The first to ask runs it.
    pub(super) fn joins_a_shared_check(&mut self, attachment: Attachment, action: &Action) -> bool {
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
    pub(super) fn on_shared_check(&mut self, event: ProtocolEvent) {
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
                self.drive(validator, |p, fold| p.on_event(fold, event.clone()));
            }
            self.drive(last, |p, fold| p.on_event(fold, event));
        }
    }

    /// Run one participant's beacon-owned delegated action on the
    /// consensus dispatch pool, behind its release gate. Its outcomes
    /// return to that participant as continuations.
    pub(super) fn dispatch_participant_action(&self, validator: ValidatorId, action: Action) {
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
}

/// One identity's beacon participation on the loop.
pub(super) struct Participant {
    pub(super) attachment: Attachment,
    pub(super) duty: BeaconParticipant,
    signer: Arc<dyn Signer>,
    /// The release gate every signature the participant dispatches
    /// enters, closed when the participant is removed.
    pub(super) gate: Arc<Gate>,
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
pub(super) enum SharedCheck {
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

    pub(super) const fn of_outcome(event: &ProtocolEvent) -> Option<Self> {
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
