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
use hyperscale_beacon::action_handlers::verify_beacon_block;
use hyperscale_beacon::coordinator::retention_floor;
use hyperscale_beacon::{Adopted, BeaconFold, CandidateKeys, ChainRegistration};
use hyperscale_core::{Action, FetchIds, FetchRequest, ParticipationChange, ProtocolEvent};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_network::Network;
use hyperscale_storage::{BeaconStorage, ShardStorage};
use hyperscale_types::network::gossip::ShardVoteEquivocationGossip;
use hyperscale_types::{
    BeaconState, BlockHeight, CandidateBeaconBlock, CandidateVerifyContext, CertifiedBlockHeader,
    Epoch, GenesisConfigHash, Hash, LocalTimestamp, NetworkDefinition, ShardId,
    ShardVoteEquivocation, SlotEffects, TopologySchedule, ValidatorId, Verifiable, Verified,
    Verifier, verify_shard_vote_equivocation,
};
use tracing::warn;

use crate::beacon::{self, BeaconBlockSync, BeaconFetchState, BeaconReply, ProposalKeys};
use crate::config::NodeConfig;
use crate::event::{Attachment, BeaconOwner, BeaconScopedInput, HostEvent};
use crate::fetch::Release;
use crate::process::ProcessIo;
use crate::shard::mempool::DeferredForRecords;
use crate::shard::{FetchTicker, StepOutput, TimerOp};

mod block_sync;
mod chains;
mod interest;
mod participants;
mod records;
mod submissions;

use interest::{Asked, Askers, Interest};
use participants::{Participant, SharedCheck};
pub(crate) use records::custodian;

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

    /// The host's fold.
    #[must_use]
    pub(crate) const fn fold(&self) -> &BeaconFold {
        &self.fold
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
                    self.drive(attachment.validator, |p, fold| p.on_event(fold, *event));
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
                self.tick_fetches();
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
                    self.drive(validator, |p, fold| p.on_event(fold, other.clone()));
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

    /// Handle the actions the fold emitted: the effects any owner's
    /// actions have, and its block checks on the dispatch pool.
    fn run_fold_actions(&mut self, actions: Vec<Action>) {
        self.actions_generated += actions.len();
        for action in actions {
            match self.process_shared_action(BeaconOwner::Fold, action) {
                None => {}
                Some(action @ Action::VerifyBeaconBlock { .. }) => {
                    self.dispatch_block_check(action);
                }
                Some(other) => warn!(
                    action = other.type_name(),
                    "BeaconLoop: an action the fold does not emit — dropping"
                ),
            }
        }
    }

    /// Carry out one of the loop's own effects that the fold and the
    /// participants alike emit — commit, topology, seat trigger, catch-up
    /// sync, fetches, commit-proof asks — on `owner`'s behalf. Any other
    /// action comes back for its owner's own handler.
    pub(super) fn process_shared_action(
        &mut self,
        owner: BeaconOwner,
        action: Action,
    ) -> Option<Action> {
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
            other => return Some(other),
        }
        None
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

#[cfg(test)]
mod tests;
