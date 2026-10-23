//! Per-host driver for beacon participation: the beacon loop.
//!
//! A [`BeaconLoop`] runs on every host. It drives the vnodes the host runs
//! with `shard: None` — logical nodes that follow the beacon chain (adopt
//! committed beacon blocks, track topology, surface their own seat
//! triggers) but run no shard consensus — and owns the host's beacon-block
//! catch-up sync and the proposal and candidate fetches its participants
//! ask for. It is the lightweight sibling of
//! [`ShardLoop`](crate::shard::ShardLoop): a `Vec<Vnode>` plus a cloned
//! `Arc<ProcessIo>` and per-step scratch, with no `ShardIo` and no batch
//! accumulators.
//!
//! Loop effects (the beacon commit, topology, seat triggers, timers, the
//! catch-up sync and fetches) run inline. Beacon-owned delegated actions
//! run on the consensus dispatch pool through the same
//! [`hyperscale_beacon::action_handlers`] a seated vnode's dispatch runs,
//! over the storage-free `BeaconActionContext`, and each outcome returns
//! to the participant that emitted the action as a
//! [`BeaconScopedInput::Continuation`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_beacon::action_handlers::handle_action as handle_beacon_action;
use hyperscale_core::{
    Action, ActionOwner, BeaconActionContext, FetchIds, FetchRequest, ParticipationChange,
    ProtocolEvent, StateMachine,
};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_network::{Answerers, Network, RequestError, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::beacon::GetBeaconBlockRequest;
use hyperscale_types::network::response::beacon::GetBeaconBlockResponse;
use hyperscale_types::{
    BeaconBlockHash, BeaconProposal, CandidateBeaconBlock, CertifiedBeaconBlock, Epoch,
    LocalTimestamp, MessageClass, ShardId, TopologySnapshot, ValidatorId, ValidatorStatus,
    Verifiable, Verified,
};
use tracing::{trace, warn};

use crate::beacon::{
    self, BeaconBlockSync, BeaconCandidateBinding, BeaconFetchState, BeaconProposalBinding,
    BeaconReply, BeaconSyncSink, beacon_block_sync_config,
};
use crate::config::NodeConfig;
use crate::event::{Attachment, BeaconOwner, BeaconScopedInput, HostEvent, classify_fetch_error};
use crate::fetch::{FetchInput, FetchOutput, FetchedBy, Release};
use crate::process::ProcessIo;
use crate::shard::{FetchTicker, StepOutput, TimerOp, TimerOwner};
use crate::vnode::Vnode;

/// The host's beacon driver.
pub struct BeaconLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    /// Process-scoped resources shared with every other driver on the host:
    /// beacon storage, the beacon-commit dedup gate, the topology `ArcSwap`.
    pub(crate) process: Arc<ProcessIo<S, N, D>>,

    /// The shard-less vnodes this host follows the beacon with, each under
    /// its own attachment. Driven in order each step; each independently
    /// folds the same committed beacon blocks.
    participants: Vec<Participant>,

    /// Cached wall-clock time, set by [`NodeHost::set_time`](crate::host::NodeHost::set_time).
    now: LocalTimestamp,

    /// Per-step scratch: placement deltas emitted via
    /// `Action::ReconfigureParticipation` — the seat/drain triggers the runner
    /// acts on. Cleared at step entry, drained into the step's `StepOutput`.
    pub(crate) pending_participation_changes: Vec<ParticipationChange>,

    /// Per-step scratch: timer operations, each owned by the participant
    /// that armed it or by the loop for its fetch tick. A participant is a
    /// ratify-pool voter and can be drawn onto an SPC committee, so its
    /// beacon timer chain must stay live.
    pub(crate) pending_timer_ops: Vec<TimerOp>,

    /// Per-step scratch: count of actions the participants produced.
    pub(crate) actions_generated: usize,

    /// Beacon-block catch-up sync, scope `()`. A participant emits
    /// `Action::StartBeaconBlockSync` when a gossiped block sits more than
    /// one epoch ahead of its tip; this FSM drives the
    /// `GetBeaconBlockRequest` fetches that close the gap.
    beacon_block: BeaconBlockSync,

    /// The proposal and candidate fetches the participants ask for.
    fetches: BeaconFetchState,

    /// Which participants want each proposal and candidate id.
    interest: Interest,

    /// Where the fetches' answers return: the host's beacon channel.
    reply: BeaconReply,

    /// The one fetch tick that retries both the fetches and the sync.
    fetch_tick: FetchTicker,
}

impl<S, N, D> BeaconLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Build the host's beacon loop over its shard-less vnodes. Used by
    /// `NodeHost::new` at construction and by the production supervisor
    /// when it rebuilds the loop's follower set at runtime.
    ///
    /// Every follower's beacon startup timers are armed into the timer
    /// scratch here; the caller drains them to its timer table (the sim
    /// through the construction-time `drain_pending_output`, the
    /// production beacon thread by re-arming at spawn).
    pub fn new(process: Arc<ProcessIo<S, N, D>>, vnodes: Vec<Vnode>, config: &NodeConfig) -> Self {
        let reply = BeaconReply(process.beacon_event_sender.clone());
        let participants = vnodes
            .into_iter()
            .map(|vnode| Participant {
                attachment: process.attach(vnode.validator_id),
                vnode,
            })
            .collect();
        let mut beacon = Self {
            process,
            participants,
            now: LocalTimestamp::ZERO,
            pending_participation_changes: Vec::new(),
            pending_timer_ops: Vec::new(),
            actions_generated: 0,
            beacon_block: BeaconBlockSync::new(beacon_block_sync_config()),
            fetches: BeaconFetchState::past_the_host(config),
            interest: Interest::default(),
            reply,
            fetch_tick: FetchTicker::default(),
        };
        beacon.arm_startup_timers();
        beacon
    }

    /// Add a follower at runtime — a validator that drained off its last
    /// shard — arming its beacon startup timers into the timer scratch for
    /// the caller to drain.
    pub(crate) fn add_vnode(&mut self, vnode: Vnode) {
        self.participants.push(Participant {
            attachment: self.process.attach(vnode.validator_id),
            vnode,
        });
        self.arm_beacon_startup(self.participants.len() - 1);
    }

    /// Remove `validator`'s follower. Its release gate closes before this
    /// returns, so none of its signatures leaves the host afterwards, and
    /// the fetches only it asked for are released. What its attachment
    /// left in flight, continuations and timers alike, is dropped on
    /// arrival. The fetch tick is left as it stands, so removal pushes no
    /// timer op: a tick that finds nothing pending lapses on its own.
    pub(crate) fn remove_vnode(&mut self, validator: ValidatorId) {
        let Some(idx) = self
            .participants
            .iter()
            .position(|p| p.attachment.validator == validator)
        else {
            return;
        };
        let participant = self.participants.remove(idx);
        participant.vnode.gate.close_and_wait();
        let owner = BeaconOwner::Participant(participant.attachment);
        self.forget::<BeaconProposalBinding>(owner);
        self.forget::<BeaconCandidateBinding>(owner);
    }

    /// The validators the loop follows the beacon for, in attach order.
    pub fn validators(&self) -> impl Iterator<Item = ValidatorId> + '_ {
        self.participants.iter().map(|p| p.attachment.validator)
    }

    /// Arm every follower's beacon startup timers into the timer scratch.
    /// Idempotent: re-arming replaces the pending fire at the runner's
    /// table, and the durations recompute identically from each
    /// coordinator's clock.
    fn arm_startup_timers(&mut self) {
        for vnode_idx in 0..self.participants.len() {
            self.arm_beacon_startup(vnode_idx);
        }
    }

    /// Re-arm every follower's beacon startup timers and drain the result —
    /// the production beacon thread's spawn-time bootstrap. Replayable: the
    /// construction-time arming may already have been drained by a genesis
    /// ceremony on the host, and re-arming is idempotent.
    pub fn startup_output(&mut self) -> StepOutput {
        self.clear_scratch();
        self.arm_startup_timers();
        self.take_output()
    }

    /// Drive one follower's startup arming through the action path, so the
    /// emitted `SetTimer`s land in the timer scratch like any other step's.
    fn arm_beacon_startup(&mut self, vnode_idx: usize) {
        let actions = self.participants[vnode_idx]
            .vnode
            .state
            .beacon_startup_actions();
        self.actions_generated += actions.len();
        for action in actions {
            self.process_action(vnode_idx, action);
        }
    }

    /// Set the cached wall-clock time observed by `state.handle(now, _)`.
    pub const fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
    }

    /// Number of followers.
    #[must_use]
    pub(crate) const fn len(&self) -> usize {
        self.participants.len()
    }

    /// Whether the loop holds no followers.
    #[must_use]
    pub(crate) const fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }

    /// Clear per-step scratch. Called by [`NodeHost::step`](crate::host::NodeHost::step)
    /// before dispatch so the drained output reflects only this step.
    pub(crate) fn clear_scratch(&mut self) {
        self.pending_participation_changes.clear();
        self.pending_timer_ops.clear();
        self.actions_generated = 0;
    }

    /// Drive one beacon input and return the step's output: the placement
    /// deltas the followers surfaced (the seat triggers the supervisor
    /// acts on) and the timer operations. Clears per-step scratch first,
    /// mirroring [`ShardLoop::run_step`](crate::shard::ShardLoop::run_step);
    /// used by the production beacon thread, which owns the `BeaconLoop`
    /// directly rather than driving it through
    /// [`NodeHost::step`](crate::host::NodeHost::step).
    pub fn run_step(&mut self, input: BeaconScopedInput) -> StepOutput {
        self.clear_scratch();
        self.dispatch_event(input);
        self.take_output()
    }

    /// Drain this step's scratch into a [`StepOutput`]. A follower emits no
    /// transaction statuses, so that field stays empty; the counterpart to
    /// [`Self::clear_scratch`], used by both this loop's [`Self::run_step`]
    /// and the whole-host [`NodeHost::step`](crate::host::NodeHost::step) so
    /// the scratch field set lives in one place.
    pub(crate) fn take_output(&mut self) -> StepOutput {
        StepOutput {
            actions_generated: std::mem::replace(&mut self.actions_generated, 0),
            timer_ops: std::mem::take(&mut self.pending_timer_ops),
            participation_changes: std::mem::take(&mut self.pending_participation_changes),
            ..StepOutput::default()
        }
    }

    /// Route a [`BeaconScopedInput`] to the followers, the fetches or the
    /// catch-up sync, then keep the fetch tick armed exactly while either
    /// has work pending.
    pub(crate) fn dispatch_event(&mut self, input: BeaconScopedInput) {
        match input {
            BeaconScopedInput::Protocol(event) => self.dispatch_protocol(*event),
            BeaconScopedInput::Continuation {
                owner: BeaconOwner::Participant(participant),
                event,
            }
            | BeaconScopedInput::ParticipantTimer { participant, event } => {
                if let Some(vnode_idx) = self.participant_index(participant) {
                    self.drive(vnode_idx, *event);
                }
            }
            BeaconScopedInput::BeaconBlockSyncResponseReceived { epoch, block } => {
                beacon::on_response(self, epoch, block);
            }
            BeaconScopedInput::BeaconBlockSyncFetchFailed { epoch, kind } => {
                beacon::on_fetch_failed(self, epoch, kind);
            }
            BeaconScopedInput::FetchFailed(ids) => self.release(ids, Release::Failed),
            BeaconScopedInput::FetchUnroutable(ids) => self.release(ids, Release::Unroutable),
            BeaconScopedInput::FetchFulfilled(ids) => self.release(ids, Release::Admitted),
            BeaconScopedInput::FetchTick => {
                self.fetch_tick.fired();
                self.drive_fetch::<BeaconProposalBinding>(FetchInput::Tick);
                self.drive_fetch::<BeaconCandidateBinding>(FetchInput::Tick);
                beacon::on_tick(self);
            }
        }
        self.update_fetch_tick_timer();
    }

    fn participant_index(&self, attachment: Attachment) -> Option<usize> {
        self.participants
            .iter()
            .position(|p| p.attachment == attachment)
    }

    /// Fan a beacon [`ProtocolEvent`] across every follower.
    fn dispatch_protocol(&mut self, event: ProtocolEvent) {
        let count = self.participants.len();
        if count == 0 {
            return;
        }
        // Clone for every vnode except the last; the last takes ownership.
        for vnode_idx in 0..count - 1 {
            self.drive(vnode_idx, event.clone());
        }
        self.drive(count - 1, event);
    }

    /// Feed `event` to one follower and handle the actions it emits.
    fn drive(&mut self, vnode_idx: usize, event: ProtocolEvent) {
        let actions = self.participants[vnode_idx]
            .vnode
            .state
            .handle(self.now, event);
        self.actions_generated += actions.len();
        for action in actions {
            self.process_action(vnode_idx, action);
        }
    }

    /// Handle one action from a follower: the loop-internal effects
    /// (commit, topology, seat trigger, timer op, catch-up sync, fetches)
    /// inline, and every beacon-owned delegated action on the dispatch
    /// pool — a pooled validator can sit in the ratify pool or on an SPC
    /// committee while its seat is still pending, and its votes and
    /// proposals must flow. Anything else belongs to shard consensus,
    /// which a follower never runs.
    fn process_action(&mut self, vnode_idx: usize, action: Action) {
        let me = self.participants[vnode_idx].attachment;
        let owner = BeaconOwner::Participant(me);
        match action {
            Action::CommitBeaconBlock { block, state } => {
                // Process-scoped dedup: the first vnode to reach this
                // `(epoch, hash)` writes to the host's beacon storage. A pooled
                // vnode no-ops `BeaconBlockPersisted`, so it isn't fed back.
                self.process
                    .beacon_commit
                    .commit(&self.process.beacon_storage, &block, &state);
                // Advance the sync FSM's committed watermark on every commit
                // (gossip or sync) so a serial catch-up unblocks the next
                // epoch's fetch and a later sync starts above every hosted
                // tip.
                beacon::on_admitted(self);
            }
            Action::TopologyChanged { epoch, schedule } => {
                self.process.apply_topology(epoch, schedule);
            }
            Action::ReconfigureParticipation(change) => {
                self.pending_participation_changes.push(change);
            }
            // A follower's beacon timer chain is liveness-critical: it is a
            // ratify-pool voter (`BeaconRatifyTrigger` starts and paces its
            // skip rounds) and can be drawn onto an SPC committee
            // (`BeaconCommitteeStart` and the SPC timers). Buffer the ops for
            // the runner's timer table, owned by this follower alone.
            Action::SetTimer { id, duration } => {
                self.pending_timer_ops.push(TimerOp::Set {
                    owner: TimerOwner::Participant(me),
                    id,
                    duration,
                });
            }
            Action::CancelTimer { id } => {
                self.pending_timer_ops.push(TimerOp::Cancel {
                    owner: TimerOwner::Participant(me),
                    id,
                });
            }
            // Catch-up sync: a follower fell behind a gossiped block, so drive
            // the FSM to fetch the missing epochs from a live committee.
            Action::StartBeaconBlockSync { target } => {
                beacon::start(self, target);
            }
            Action::Fetch(FetchRequest::Ask {
                ids,
                preferred,
                class,
                ..
            }) => {
                if let Some(shard) = self.ask_shard(vnode_idx, preferred) {
                    self.ask(owner, ids, shard, preferred, class);
                } else {
                    warn!("BeaconLoop: no live shard with a committee to ask; dropping");
                }
            }
            Action::AbandonFetch(ids) => self.abandon(owner, ids),
            other if other.owner() == ActionOwner::Beacon => {
                self.dispatch_beacon_action(vnode_idx, other);
            }
            other => {
                warn!(
                    action = other.type_name(),
                    "BeaconLoop: unexpected action from a beacon follower — dropping"
                );
            }
        }
    }

    /// Run one beacon-owned delegated action on the consensus dispatch
    /// pool, behind the same signing fences the shard dispatch applies and
    /// the follower's release gate. Its outcomes return to the follower
    /// that emitted it as continuations.
    fn dispatch_beacon_action(&self, vnode_idx: usize, action: Action) {
        let Participant { attachment, vnode } = &self.participants[vnode_idx];
        let attachment = *attachment;
        let me = attachment.validator;
        // The process-level signing fences, shared with every seated vnode of
        // the same validator: one ratify signature per position, one SPC view
        // claim per epoch — a seat racing this follower's retirement cannot
        // double-sign. The loop claims views as `None`, a claimant no hosted
        // shard can alias (a single-shard network's only leaf is
        // `ShardId::ROOT`).
        if let Some(position) = action.ratify_signing_position() {
            if !self.process.allow_ratify_signing(me, position) {
                trace!(
                    validator = ?me,
                    epoch = position.0.inner(),
                    round = position.1.inner(),
                    "BeaconLoop: dropping already-covered ratify vote position"
                );
                return;
            }
        } else if let Some((epoch, view)) = action.beacon_signing_position()
            && !self.process.allow_beacon_signing(me, None, epoch, view)
        {
            trace!(
                validator = ?me,
                epoch = epoch.inner(),
                view = view.inner(),
                action = action.type_name(),
                "BeaconLoop: dropping beacon signing action for an unclaimed view"
            );
            return;
        }

        let handles = Arc::clone(&self.process.dispatch_handles);
        let topology_snapshot = Arc::clone(vnode.state.topology_arc());
        let signer = Arc::clone(&vnode.signer);
        let gate = Arc::clone(&vnode.gate);
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
                    me,
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

    /// Ask for `ids` on `owner`'s behalf over `shard`'s committee.
    fn ask(
        &mut self,
        owner: BeaconOwner,
        ids: FetchIds,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
    ) {
        match ids {
            FetchIds::BeaconProposals(ids) => {
                self.ask_for::<BeaconProposalBinding>(owner, ids, shard, preferred, class);
            }
            FetchIds::BeaconCandidates(ids) => {
                self.ask_for::<BeaconCandidateBinding>(owner, ids, shard, preferred, class);
            }
            other => trace!(
                ids = ?other,
                "BeaconLoop: dropping a fetch the beacon loop does not drive"
            ),
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
        match ids {
            FetchIds::BeaconProposals(ids) => self.abandon_for::<BeaconProposalBinding>(owner, ids),
            FetchIds::BeaconCandidates(ids) => {
                self.abandon_for::<BeaconCandidateBinding>(owner, ids);
            }
            _ => {}
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
        match ids {
            FetchIds::BeaconProposals(ids) => self.release_for::<BeaconProposalBinding>(ids, how),
            FetchIds::BeaconCandidates(ids) => {
                self.release_for::<BeaconCandidateBinding>(ids, how);
            }
            _ => {}
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
    /// [`Self::fetch_shard`] when the member sits on no live shard with a
    /// committee. The participant's own fold places the member.
    fn ask_shard(&self, vnode_idx: usize, preferred: Option<ValidatorId>) -> Option<ShardId> {
        let Participant { attachment, vnode } = &self.participants[vnode_idx];
        let topology = self.process.topology_snapshot.load();
        preferred
            .and_then(|member| {
                let state = vnode.state.beacon_coordinator().current_state();
                match state.validators.get(&member)?.status {
                    ValidatorStatus::OnShard { shard, .. } => Some(shard),
                    _ => None,
                }
            })
            .filter(|&shard| answers(&topology, shard))
            .or_else(|| self.fetch_shard(Some(attachment.validator)))
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

/// Close every participant's release gate on every way the loop goes
/// away: a teardown, a panic unwinding its thread, or a crashed host.
impl<S, N, D> Drop for BeaconLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    fn drop(&mut self) {
        for participant in &self.participants {
            participant.vnode.gate.close_and_wait();
        }
    }
}

/// One identity the loop follows the beacon for.
struct Participant {
    attachment: Attachment,
    vnode: Vnode,
}

/// Whether a beacon ask over `shard` reaches anyone: a live leaf with a
/// committee.
fn answers(topology: &TopologySnapshot, shard: ShardId) -> bool {
    topology.shard_trie().contains(shard) && !topology.committee_for_shard(shard).is_empty()
}

/// Who still wants each id of one fetch. An id is released only when the
/// last owner asking for it abandons it.
type Askers<Id> = BTreeMap<Id, BTreeSet<BeaconOwner>>;

/// The owners asking each proposal and candidate id the loop fetches. The
/// entry's route, in-flight slot, failure count and tick hold stay one per
/// id in [`BeaconFetchState`], shared by every owner that wants it.
#[derive(Default)]
struct Interest {
    proposals: Askers<(Epoch, ValidatorId)>,
    candidates: Askers<(Epoch, BeaconBlockHash)>,
}

/// A beacon fetch the loop drives on behalf of several owners.
trait Asked: FetchedBy<BeaconFetchState> {
    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id>;
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

impl<S, N, D> BeaconSyncSink for BeaconLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    fn beacon_fsm(&mut self) -> &mut BeaconBlockSync {
        &mut self.beacon_block
    }

    fn deliver_block(&mut self, block: Arc<Verifiable<CertifiedBeaconBlock>>) {
        self.dispatch_protocol(ProtocolEvent::BeaconBlockSyncReadyToApply { block });
    }

    /// Ask past the host: its own beacon store is filled by the same
    /// commits the sync is waiting on.
    fn dispatch_fetch(&self, epoch: Epoch) {
        let lowest = self.validators().min();
        let Some(shard) = self.fetch_shard(lowest) else {
            warn!("BeaconLoop: no live shard to fetch beacon blocks from; deferring");
            return;
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
    }

    fn now(&self) -> LocalTimestamp {
        self.now
    }

    fn lowest_tip(&self) -> Option<Epoch> {
        self.participants
            .iter()
            .map(|p| p.vnode.state.beacon_coordinator().latest_block().epoch())
            .min()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crossbeam::channel::Receiver;
    use hyperscale_core::TimerId;
    use hyperscale_dispatch_sync::{DeferredJobs, ProcessingTimes, SyncDispatch};
    use hyperscale_network_memory::{
        HostLayout, LinkStreams, NetworkConfig, SimNetworkAdapter, SimulatedNetwork,
    };
    use hyperscale_storage::BeaconChainWriter;
    use hyperscale_storage_memory::{SimBeaconStorage, SimShardStorage};
    use hyperscale_types::network::request::beacon::GetBeaconProposalRequest;
    use hyperscale_types::network::response::beacon::GetBeaconProposalResponse;
    use hyperscale_types::{
        BeaconChainConfig, BeaconProposalDraft, BlockHeight, NetworkDefinition,
    };

    use super::*;
    use crate::shard::seated_host::{Fixture, Host, SHARD};

    type Loop = BeaconLoop<SimShardStorage, SimNetworkAdapter, SyncDispatch>;

    const PROPOSAL: (Epoch, ValidatorId) = (Epoch::new(1), ValidatorId::new(1));

    fn participant(n: u64) -> BeaconOwner {
        BeaconOwner::Participant(Attachment::new(ValidatorId::new(n), n))
    }

    fn proposals(ids: &[(Epoch, ValidatorId)]) -> FetchIds {
        FetchIds::BeaconProposals(ids.to_vec())
    }

    /// `owner` asks for `ids` through the loop, as its coordinator would.
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

    /// A host with no follower still runs its beacon loop: the loop asks
    /// for what a participant wants and arms its own fetch tick.
    #[test]
    fn every_host_runs_a_beacon_loop_with_no_follower() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        assert_eq!(host.pooled_len(), 0);
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
        let out = host.step(HostEvent::Beacon(BeaconScopedInput::FetchFulfilled(
            proposals(&[PROPOSAL]),
        )));
        assert_eq!(
            fetch_ticks(&out.timer_ops),
            vec![false],
            "an answered fetch leaves nothing pending",
        );

        beacon::start(&mut host.beacon, Epoch::new(5));
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

    /// A follower on the SPC committee asks for the proposals its dwell
    /// finds missing, and the beacon loop's fetch brings one back from a
    /// peer into its pool.
    #[test]
    fn a_follower_on_the_spc_committee_recovers_a_lost_proposal_through_the_host_fetch() {
        let fix = Fixture::new();
        let (mut wire, mut host, events) = wired(&fix, SyncDispatch::new());
        let author = fix.committee.validator_id(1);
        host.add_pooled_vnode(fix.follower(&host, 2));
        let _ = host.drain_pending_output();

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

        let follower = host.beacon.participants[0].attachment;
        let timer = |event| {
            HostEvent::Beacon(BeaconScopedInput::ParticipantTimer {
                participant: follower,
                event: Box::new(event),
            })
        };
        let _ = host.step(timer(ProtocolEvent::BeaconCommitteeStartTimer));
        wire.pump(&mut host, &events);
        let pool = |host: &Host| {
            host.beacon.participants[0]
                .vnode
                .state
                .beacon_coordinator()
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
            "the dwell's fetch brings the lost proposal into the follower's pool",
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

        beacon::start(&mut host.beacon, Epoch::new(1));
        wire.pump(&mut host, &events);
        assert_eq!(
            here.load(Ordering::SeqCst),
            0,
            "the host's own store is not asked"
        );
        assert_eq!(there.load(Ordering::SeqCst), 1);
    }

    /// A signature a follower's dispatch queued before the follower left
    /// the loop never leaves the host: removal closes its release gate.
    #[test]
    fn a_dropped_followers_queued_signature_never_leaves() {
        let fix = Fixture::new();
        let jobs = Arc::new(DeferredJobs::new(ProcessingTimes::disk(7), 7));
        let (_wire, mut host, _events) = wired(&fix, SyncDispatch::deferred(Arc::clone(&jobs)));
        let follower = fix.committee.validator_id(2);
        host.add_pooled_vnode(fix.follower(&host, 2));
        let _ = host.drain_pending_output();

        // Past epoch 0's boundary plus the skip timeout, so the ratify
        // tracker prevotes the skip hash.
        host.set_time(past_the_skip_timeout());
        let _ = host.step(ratify_timer(host.beacon.participants[0].attachment));
        let queued = jobs.take();
        assert!(!queued.is_empty(), "the skip prevote is queued on the pool");

        host.drop_pooled_vnode(follower);
        for (_, job) in queued {
            job();
        }
        assert!(
            host.beacon_storage().ratify_record(follower).is_none(),
            "no ratify slot is spent, so no prevote was signed",
        );
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

    /// An identity dropped and attached again is a new attachment: what
    /// the old one left in flight is dropped on arrival, and only the new
    /// one's own outcomes reach it.
    #[test]
    fn a_reattached_identity_never_sees_its_predecessors_continuation() {
        let fix = Fixture::new();
        let jobs = Arc::new(DeferredJobs::new(ProcessingTimes::disk(7), 7));
        let (_wire, mut host, _events) = wired(&fix, SyncDispatch::deferred(Arc::clone(&jobs)));
        let follower = fix.committee.validator_id(2);
        host.add_pooled_vnode(fix.follower(&host, 2));
        let predecessor = host.beacon.participants[0].attachment;
        host.drop_pooled_vnode(follower);
        host.add_pooled_vnode(fix.follower(&host, 2));
        let successor = host.beacon.participants[0].attachment;
        let _ = host.drain_pending_output();
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

    /// Dropping the loop, however it goes away, closes every follower's
    /// release gate.
    #[test]
    fn dropping_the_beacon_loop_closes_its_followers_gates() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        host.add_pooled_vnode(fix.follower(&host, 2));
        let gate = Arc::clone(&host.beacon.participants[0].vnode.gate);
        assert!(gate.enter().is_some(), "a live follower's gate is open");
        drop(host);
        assert!(gate.enter().is_none(), "the dropped loop closed it");
    }

    /// A proposal ask goes to the committee of the author it prefers, as
    /// the asker's fold places it; an author on no live shard with a
    /// committee falls back to the live-leaf rule.
    #[test]
    fn a_proposal_ask_goes_to_its_authors_shard() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        let id = |idx| fix.committee.validator_id(idx);
        let (left, right) = ShardId::ROOT.children();
        host.process
            .topology_snapshot
            .store(Arc::new(fix.topology(BTreeMap::from([
                (left, vec![id(0), id(1)]),
                (right, vec![id(2), id(3)]),
            ]))));
        let asker = id(2);
        let spread = host
            .beacon
            .fetch_shard(Some(asker))
            .expect("both leaves carry a committee");
        let away = if spread == left { right } else { left };

        // The asker's fold places `id(1)` on `away`; genesis leaves `id(3)`
        // on the root, which is no live leaf.
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
        let storage = SimBeaconStorage::new();
        storage.commit_beacon_block(&fix.genesis_block(), &Arc::new(state));
        host.add_pooled_vnode(fix.follower_over(&storage, 2));
        let _ = host.drain_pending_output();
        let _ = host.network().drain_pending_requests();

        let mut routed = |author: ValidatorId| {
            host.beacon.process_action(
                0,
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
}
