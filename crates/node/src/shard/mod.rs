//! Per-shard scope: the I/O state, core infrastructure, and the driver
//! ([`ShardLoop`]) for one hosted shard.
//!
//! [`ShardIo`] ([`io`]) composes one shard's per-subsystem state —
//! [`consensus`], [`cross_shard`] and [`mempool`] — over shared infra (storage, the [`commit`] pipeline,
//! request-serving [`caches`]). [`ShardLoop`] is the active driver: it owns the
//! `ShardIo`, the shard's one replica and the signers attached to it,
//! per-step scratch, and a cloned `Arc<ProcessIo>`. `ShardLoop::step(input)`
//! dispatches one [`ShardScopedInput`] to its handler.
//!
//! The top-level [`NodeHost`] composes one `ShardLoop` per hosted shard plus
//! the shared `ProcessIo`. Cross-shard concerns (transaction submission
//! fan-out, fetch tick, batch flush coordination) live on `NodeHost`; per-shard
//! concerns live here. The dispatch match below is the thin router; each
//! subsystem's `impl ShardLoop` glue lives beside its state under
//! [`consensus`], [`cross_shard`], and [`mempool`].
//!
//! [`NodeHost`]: crate::host::NodeHost

// Per-shard state, grouped by subsystem over shared infra. Crate-internal —
// `shard` is `pub` for its driver types (ShardLoop, HostEvent, …), but the
// subsystem internals are not part of the crate's external API.
pub(crate) mod boundary_pins;
pub(crate) mod caches;
pub(crate) mod commit;
pub(crate) mod consensus;
pub(crate) mod cross_shard;
pub(crate) mod crossing_index;
pub(crate) mod instances;
pub(crate) mod io;
pub(crate) mod mempool;
pub(crate) mod phase_times;
pub(crate) mod verify;

// The driver shell: dispatch, lifecycle, metrics, the generic
// fetch/timer plumbing, and the consensus driver glue.
mod actions;
mod fetch_dispatch;
mod lifecycle;
pub use lifecycle::{installed_network_genesis_block, network_genesis_block};
mod metrics;
mod protocol_event;
#[cfg(test)]
pub(crate) mod test_host;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam::channel::{Sender, TrySendError};
pub(crate) use fetch_dispatch::FetchTicker;
use hyperscale_beacon::ChainRegistration;
use hyperscale_core::{Action, ParticipationChange, ProtocolEvent, StateMachine, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{Executor, RecordStore};
use hyperscale_metrics::record_network_input_refused;
use hyperscale_network::{Network, Provenance};
use hyperscale_storage::{
    AnswerFollow, BeaconStorage, PendingChain, RecoveredState, ShardStorage, TickChain,
};
use hyperscale_types::{
    Address, Block, CertifiedBlock, Hash, LocalTimestamp, QuorumCertificate, Round, ShardId,
    Signer, TopologySnapshot, TransactionStatus, TxHash, ValidatorId, Verified, shard_prefix_path,
};
pub use io::ShardIo;

use crate::batch_accumulator::BatchAccumulator;
use crate::beacon::{BeaconCandidateCache, BeaconProposalCache};
use crate::event::Attachment;
pub use crate::event::{
    BeaconScopedInput, EventPriority, FetchFailureKind, HostEvent, NETWORK_LANE_CAPACITY,
    ProcessScopedInput, ShardInbox, ShardScopedInput,
};
use crate::fetch::Release;
use crate::process::ProcessIo;
use crate::replica::AttachedSigner;
use crate::shard::commit::PreparedCommitMap;
use crate::state::NodeStateMachine;

/// Lock-free shared topology snapshot for handler closures and dispatch.
///
/// Updated by the host when `Action::TopologyChanged` is processed.
/// Handler closures call `.load()` to get the current snapshot atomically.
pub type SharedTopologySnapshot = Arc<ArcSwap<TopologySnapshot>>;

/// Long-lived handles cloned into every delegated-action dispatch.
///
/// Wrapped in a single `Arc` so each dispatch pays one atomic-RMW for
/// the whole bundle. `topology_snapshot`, `event_sender`, and the
/// signing key are not bundled — the snapshot needs a fresh `load_full`
/// per dispatch, the crossbeam `Sender` clone is independent of these
/// handles, and the key is the attached signer's the action names.
///
/// Shard-scoped handles (`pending_chain`, `prepared_commits`) live in
/// `per_shard`, keyed by the hosted shard id. Delegated handlers select
/// the right entry from the emitting loop's shard, loading the map per
/// dispatch so shards added or dropped at runtime are observed.
pub(crate) struct DispatchHandles<S: ShardStorage, N> {
    pub(crate) executor: Arc<Executor>,
    pub(crate) network: Arc<N>,
    /// Process-level serve cache for beacon proposals — fed by the
    /// `BuildAndBroadcastBeaconProposal` handler and the wire
    /// notification handler, read by the `GetBeaconProposalRequest`
    /// responder. No coordinator touches it.
    pub(crate) beacon_proposal_cache: Arc<BeaconProposalCache>,
    /// Process-level serve cache for ratify candidates — fed by the
    /// candidate broadcast and verify handlers, read by the
    /// `GetBeaconCandidateRequest` responder.
    pub(crate) beacon_candidate_cache: Arc<BeaconCandidateCache>,
    /// Process-level beacon store, threaded to the ratify-vote sign
    /// handler as its durable-register seam.
    pub(crate) beacon_storage: Arc<dyn BeaconStorage>,
    /// Behind its own `Arc` so the stores can be shared with the engine
    /// without the engine holding the handles that hold the engine.
    pub(crate) per_shard: Arc<ArcSwap<HashMap<ShardId, ShardDispatchHandles<S>>>>,
}

/// The component records this node keeps on disk: the cells of every
/// shard it hosts, and the copies it fetched of everyone else's.
///
/// A component's record lives in a cell under the component's own
/// prefix, so at most one hosted store can hold any given key and asking
/// each in turn answers without a topology lookup. Where the prefix
/// belongs to a shard this node does not serve, the answer is the copy
/// the record fetch persisted — which survives a restart and the cache
/// letting the record go alike — or nothing, where it never fetched one.
pub(crate) struct HostedRecords<S: ShardStorage> {
    per_shard: Arc<ArcSwap<HashMap<ShardId, ShardDispatchHandles<S>>>>,
    beacon_storage: Arc<dyn BeaconStorage>,
}

impl<S: ShardStorage> HostedRecords<S> {
    pub(crate) fn new(
        per_shard: Arc<ArcSwap<HashMap<ShardId, ShardDispatchHandles<S>>>>,
        beacon_storage: Arc<dyn BeaconStorage>,
    ) -> Self {
        Self {
            per_shard,
            beacon_storage,
        }
    }
}

impl<S: ShardStorage> RecordStore for HostedRecords<S> {
    fn instance_record(&self, instance: Address) -> Option<Vec<u8>> {
        let key = Executor::instance_record_key(instance);
        self.per_shard
            .load()
            .values()
            .find_map(|handles| {
                let storage = &handles.storage;
                // The committed tip, never a pending one: the caches this
                // stands behind are grown by commits, and a pending block
                // two nodes disagree about would derive an envelope two
                // ways.
                storage
                    .get_substate_at_height(key, storage.jmt_height())
                    .flatten()
            })
            .or_else(|| self.beacon_storage.fetched_instance(instance))
    }
}

impl<S: ShardStorage, N> DispatchHandles<S, N> {
    /// Install the dispatch handles for a newly hosted `shard`. The
    /// reconfiguring thread is the sole writer; readers keep their
    /// loaded snapshot.
    pub(crate) fn insert_shard(&self, shard: ShardId, handles: ShardDispatchHandles<S>) {
        let mut map = (**self.per_shard.load()).clone();
        map.insert(shard, handles);
        self.per_shard.store(Arc::new(map));
    }

    /// Drop the dispatch handles for a no-longer-hosted `shard`.
    /// In-flight dispatches keep the handles their loaded snapshot
    /// carries until they complete.
    pub(crate) fn remove_shard(&self, shard: ShardId) {
        let mut map = (**self.per_shard.load()).clone();
        map.remove(&shard);
        self.per_shard.store(Arc::new(map));
    }
}

/// Per-shard subset of [`DispatchHandles`]. One entry per hosted shard.
pub(crate) struct ShardDispatchHandles<S: ShardStorage> {
    pub(crate) storage: Arc<S>,
    pub(crate) pending_chain: Arc<PendingChain<S>>,
    pub(crate) tick_chain: Arc<TickChain<S>>,
    pub(crate) prepared_commits: Arc<Mutex<PreparedCommitMap>>,
}

impl<S: ShardStorage> Clone for ShardDispatchHandles<S> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            pending_chain: Arc::clone(&self.pending_chain),
            tick_chain: Arc::clone(&self.tick_chain),
            prepared_commits: Arc::clone(&self.prepared_commits),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TimerOp — buffered timer operations for the runner
// ═══════════════════════════════════════════════════════════════════════

/// Whose timer a [`TimerOp`] names, and so whom its fire reaches.
///
/// Each beacon participant arms the same [`TimerId`]s against its own
/// deadlines, so a participant's timer is its own and its fire reaches it
/// alone. A shard loop's timers, its replica's and its fetch tick, are the
/// loop's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TimerOwner {
    /// A hosted shard's loop: its replica's timers and its fetch tick.
    Loop(ShardId),
    /// One attached identity's beacon participation on the host's beacon
    /// loop.
    Participant(Attachment),
    /// The host's beacon loop itself: its fetch tick.
    Beacon,
}

/// A timer operation buffered by a loop driver for the runner to process.
///
/// The runner's timer driver keys handles by `(TimerOwner, TimerId)`, and
/// the firing path ([`timer_event`]) addresses the envelope to the owner.
#[derive(Debug, Clone)]
pub enum TimerOp {
    /// Set a timer to fire after `duration`.
    Set {
        /// Whose timer this is.
        owner: TimerOwner,
        /// Logical timer identifier (state-machine-side).
        id: TimerId,
        /// How long until the timer should fire.
        duration: Duration,
    },
    /// Cancel a previously set timer.
    Cancel {
        /// Whose timer this is.
        owner: TimerOwner,
        /// Logical timer identifier to cancel.
        id: TimerId,
    },
}

/// Translate a fired [`TimerId`] back into the [`HostEvent`] the runner
/// pushes onto its event channel.
///
/// The envelope is addressed to the timer's owner: a loop's timer to its
/// shard, a participant's to that participant alone, and the beacon loop's
/// fetch tick to the beacon loop.
#[must_use]
pub fn timer_event(id: &TimerId, owner: TimerOwner) -> HostEvent {
    let event = match id {
        TimerId::ViewChange => ProtocolEvent::ViewChangeTimer,
        TimerId::Cleanup => ProtocolEvent::CleanupTimer,
        TimerId::ProposalPace => ProtocolEvent::ProposalPaceTimer,
        TimerId::ProposalFetch => ProtocolEvent::ProposalFetchTimer,
        TimerId::FetchTick => {
            return match owner {
                TimerOwner::Loop(shard) => HostEvent::shard(shard, ShardScopedInput::FetchTick),
                TimerOwner::Participant(_) | TimerOwner::Beacon => HostEvent::beacon_fetch_tick(),
            };
        }
        TimerId::BeaconCommitteeStart => ProtocolEvent::BeaconCommitteeStartTimer,
        TimerId::BeaconRatifyTrigger => ProtocolEvent::BeaconRatifyTimer,
        TimerId::BeaconSpcView => ProtocolEvent::BeaconSpcViewTimer,
        TimerId::BeaconSpcInputDwell => ProtocolEvent::BeaconSpcInputDwellTimer,
    };
    match owner {
        TimerOwner::Loop(shard) => HostEvent::protocol(shard, event),
        TimerOwner::Participant(participant) => {
            HostEvent::Beacon(BeaconScopedInput::ParticipantTimer {
                participant,
                event: Box::new(event),
            })
        }
        TimerOwner::Beacon => HostEvent::beacon(event),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Event push helpers
// ═══════════════════════════════════════════════════════════════════════

/// Push a shard-scoped input into the event channel.
///
/// Off-thread closures and `ShardLoop` methods both use this to feed
/// results back to the next `step()`. The channel is unbounded; send
/// failure is silently ignored by design (the only failure mode is the
/// receiver having been dropped at shutdown, in which case there's
/// nothing to do).
pub(crate) fn push_shard_input(tx: &Sender<HostEvent>, shard: ShardId, input: ShardScopedInput) {
    let _ = tx.send(HostEvent::shard(shard, input));
}

/// Push a [`ProtocolEvent`] (wrapped in
/// [`ShardScopedInput::Protocol`]) into the event channel, for `shard`'s
/// replica.
/// See [`push_shard_input`] for the drop-on-shutdown convention.
pub(crate) fn push_protocol_event(tx: &Sender<HostEvent>, shard: ShardId, event: ProtocolEvent) {
    let _ = tx.send(HostEvent::protocol(shard, event));
}

/// Offer an input a message brought to `shard`'s network lane.
///
/// `false` when the lane is full: the input is dropped and counted, never
/// queued past the lane's bound, and the handler answers the message as
/// [`Verdict::Busy`](hyperscale_network::Verdict::Busy). A closed lane
/// takes the input as [`push_shard_input`] does. A message this host sent
/// itself ([`Provenance::Local`]) goes on the internal lane instead: the
/// bound is on what peers may queue here, not on what the host itself
/// produced.
#[must_use]
pub(crate) fn offer_network_input(
    inbox: &ShardInbox,
    shard: ShardId,
    input: ShardScopedInput,
    provenance: Provenance,
) -> bool {
    offer_network(inbox, HostEvent::shard(shard, input), provenance)
}

/// [`offer_network_input`] for a [`ProtocolEvent`].
#[must_use]
pub(crate) fn offer_network_event(
    inbox: &ShardInbox,
    shard: ShardId,
    event: ProtocolEvent,
    provenance: Provenance,
) -> bool {
    offer_network(inbox, HostEvent::protocol(shard, event), provenance)
}

fn offer_network(inbox: &ShardInbox, event: HostEvent, provenance: Provenance) -> bool {
    if provenance == Provenance::Local {
        let _ = inbox.internal().send(event);
        return true;
    }
    match inbox.network().try_send(event) {
        Ok(()) | Err(TrySendError::Disconnected(_)) => true,
        Err(TrySendError::Full(event)) => {
            if let HostEvent::Shard(shard, _) = &event {
                record_network_input_refused(shard.inner(), event.type_name());
            }
            false
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// StepOutput — returned to the caller after processing an event
// ═══════════════════════════════════════════════════════════════════════

/// Output from processing a single event via `NodeHost::step()`.
///
/// Aggregates the per-step scratch from every hosted shard touched by
/// the event: emitted transaction statuses, timer operations, action
/// counts. Sync/fetch I/O and block-commit dispatch happen internally
/// via the `Network` and `Dispatch` traits — the runner only processes
/// emitted transaction statuses and timer operations.
#[derive(Default)]
pub struct StepOutput {
    /// Transaction status notifications emitted during this step.
    pub(crate) emitted_statuses: Vec<(TxHash, TransactionStatus)>,
    /// Number of actions generated by the state machine during this step.
    pub actions_generated: usize,
    /// Timer operations (set/cancel) to be processed by the runner.
    pub timer_ops: Vec<TimerOp>,
    /// Placement deltas emitted via [`Action::ReconfigureParticipation`]
    /// during this step. The runner reconfigures physical shard
    /// membership from these — they are requests to the process layer,
    /// not state-machine state.
    pub participation_changes: Vec<ParticipationChange>,
    /// Validators the loop attached to its replica during this step.
    pub attached: Vec<ValidatorId>,
    /// Shards whose store needs a height beneath every serving peer's
    /// chain floor. Block sync can never carry such a store forward; the
    /// runner rebuilds it at the shard's attested anchor.
    pub reseats: Vec<ShardId>,
}

impl StepOutput {
    /// Fold another step's output into this one. The whole-host driver
    /// ([`NodeHost::step`](crate::host::NodeHost::step)) uses this to
    /// aggregate the per-driver outputs of every shard and the beacon loop a
    /// single event touched.
    pub(crate) fn merge(&mut self, other: Self) {
        self.emitted_statuses.extend(other.emitted_statuses);
        self.actions_generated += other.actions_generated;
        self.timer_ops.extend(other.timer_ops);
        self.participation_changes
            .extend(other.participation_changes);
        self.attached.extend(other.attached);
        self.reseats.extend(other.reseats);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ShardLoop — per-shard I/O state plus the shard's replica
// ═══════════════════════════════════════════════════════════════════════

/// Active per-shard driver: one hosted shard's [`ShardIo`], its one
/// replica and the signers attached to it, plus per-step scratch and a
/// shared `Arc<ProcessIo>`.
///
/// The replica verifies, executes and commits the shard's chain once for
/// the host, and signs for each attached validator under that validator's
/// own registers. [`Self::step`] dispatches one [`ShardScopedInput`] to its
/// handler.
pub struct ShardLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    /// Shard this loop drives. Mirrors the key in `NodeHost::shards`;
    /// held inline so methods on `ShardLoop` can self-identify without a
    /// parent-map lookup.
    pub shard: ShardId,
    /// The loop's registration with the host's beacon loop, carried by
    /// everything the loop reports to it and released when the loop
    /// closes.
    pub(crate) chain: ChainRegistration,
    /// Sender for this shard's own event channel. The channel is created
    /// with the loop and torn down with it, so the handle is cached here
    /// rather than looked up through `ProcessIo`'s swappable map on
    /// every dispatch.
    pub(crate) event_tx: Sender<HostEvent>,
    /// Process-scoped resources shared with every other hosted shard:
    /// network adapter, dispatch pool, tx validator, topology snapshot,
    /// dispatch handles, event sender. Cloned `Arc` so off-thread
    /// closures spawned from this loop's handlers can capture it cheaply.
    pub(crate) process: Arc<ProcessIo<S, N, D>>,
    /// Per-shard I/O state the replica runs over.
    pub io: ShardIo<S>,
    /// The shard's replica. Driven exclusively from this loop's thread;
    /// off-thread closures never touch it.
    pub(crate) replica: NodeStateMachine,
    /// The validators the replica signs for. Each joins through
    /// [`Self::attach_signer`] and leaves through [`Self::detach_signer`],
    /// between events; with none attached the replica follows the chain
    /// and signs nothing.
    pub(crate) signers: BTreeMap<ValidatorId, AttachedSigner>,
    /// Cached wall-clock time for this shard. Set by the runner via
    /// `NodeHost::set_time` (which propagates to every hosted shard);
    /// read by the replica's `handle(now, _)` calls and by helpers that
    /// need a single consistent stamp across an action burst.
    pub(crate) now: LocalTimestamp,
    /// This shard's `FetchTick` timer, armed while any fetch has work.
    pub(crate) fetch_tick: FetchTicker,
    /// Per-step scratch: timer set/cancel operations emitted during the
    /// step. Cleared at step entry; drained into the returned
    /// [`StepOutput`] for the runner to translate into timer-driver
    /// calls.
    pub(crate) pending_timer_ops: Vec<TimerOp>,
    /// Per-step scratch: `(tx_hash, status)` pairs emitted via
    /// `Action::EmitTransactionStatus`. Drained into [`StepOutput`].
    pub(crate) emitted_statuses: Vec<(TxHash, TransactionStatus)>,
    /// Per-step scratch: count of actions the replica produced during
    /// the step. Drained into [`StepOutput`] for the runner's metrics;
    /// reset at step entry.
    pub(crate) actions_generated: usize,
    /// Per-step scratch: validators attached during the step. Drained
    /// into [`StepOutput`].
    pub(crate) attached: Vec<ValidatorId>,
    /// Per-step scratch: whether block sync found the next height it
    /// needs beneath every serving peer's chain floor. Drained into
    /// [`StepOutput::reseats`].
    pub(crate) reseat: bool,
    /// The answers under this shard's prefix at the persisted head,
    /// followed whatever the loop's signers. One per store; `None` until
    /// the first step reads it whole.
    pub(crate) answer_follow: Option<AnswerFollow>,
}

/// A [`ShardLoop`] driven on a thread of its own.
///
/// Dropping it, as the thread returns or as a panic unwinds it, closes
/// every attached signer's gate, so nothing it queued signs after, and
/// then releases the chain's registration with the host's beacon loop,
/// so the fold stops holding the chain's windows and its commit-proof
/// asks go to another loop.
pub struct ThreadShardLoop<S, N, D>(ShardLoop<S, N, D>)
where
    S: ShardStorage,
    D: Dispatch;

impl<S, N, D> From<ShardLoop<S, N, D>> for ThreadShardLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    fn from(shard_loop: ShardLoop<S, N, D>) -> Self {
        Self(shard_loop)
    }
}

impl<S, N, D> std::ops::Deref for ThreadShardLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    type Target = ShardLoop<S, N, D>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, N, D> std::ops::DerefMut for ThreadShardLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<S, N, D> Drop for ThreadShardLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    fn drop(&mut self) {
        self.0.shut_down();
        let _ = self.0.process.beacon_event_sender.send(HostEvent::Beacon(
            BeaconScopedInput::Deregister(self.0.chain),
        ));
    }
}

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    /// Close every attached signer's gate and wait out the signatures
    /// already started: once this returns, nothing a signer of this loop
    /// signs leaves the host, and an action still queued never signs.
    pub(crate) fn shut_down(&self) {
        for attached in self.signers.values() {
            attached.gate.close_and_wait();
        }
    }

    /// The shard's replica.
    #[must_use]
    pub const fn replica(&self) -> &NodeStateMachine {
        &self.replica
    }

    /// The validators attached to the replica, in id order.
    pub fn signers(&self) -> impl Iterator<Item = ValidatorId> + '_ {
        self.signers.keys().copied()
    }
}

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Sender for this shard's own event channel — the destination for
    /// every callback this loop spawns (block-commit completions, fetch
    /// results, signature-verify outcomes) and every protocol event it pushes
    /// back to itself.
    pub(crate) const fn event_sender(&self) -> &Sender<HostEvent> {
        &self.event_tx
    }

    /// Dispatch a [`ShardScopedInput`] to its handler. Does NOT clear or
    /// drain per-step scratch — the caller (typically [`NodeHost::step`])
    /// manages the scratch lifecycle. Refreshes this shard's `FetchTick`
    /// timer once the input has fully settled so the runner sees the
    /// final Set/Cancel for `(TimerId::FetchTick, self.shard)` in the
    /// emitted timer ops.
    ///
    /// [`NodeHost::step`]: crate::host::NodeHost::step
    pub(crate) fn step(&mut self, input: ShardScopedInput) {
        self.dispatch_input(input);
        self.update_fetch_tick_timer();
    }

    /// Attach `validator` to the replica, signing with `signer` behind a
    /// fresh gate, and dispatch what it owes at once. Returns the output
    /// under [`Self::run_step`]'s contract. A validator already attached
    /// is left as it is.
    pub fn attach_signer(&mut self, validator: ValidatorId, signer: Arc<dyn Signer>) -> StepOutput {
        self.clear_scratch();
        self.attach(validator, signer);
        self.update_fetch_tick_timer();
        self.take_output()
    }

    /// [`Self::attach_signer`], leaving what it emits in the step's
    /// scratch.
    ///
    /// The attach carries the schedule the host's fold last published,
    /// installed where it is newer than the one the replica holds. The
    /// signer's record and the QC the store persisted for its committed
    /// tip are read from the live store here: a previous attachment of
    /// the validator has returned from its gate's close, so no persist of
    /// it can land after the read.
    pub(crate) fn attach(&mut self, validator: ValidatorId, signer: Arc<dyn Signer>) {
        if self.signers.contains_key(&validator) {
            return;
        }
        self.signers.insert(validator, AttachedSigner::new(signer));
        let record = self.io.storage.safe_vote_registers(validator);
        let persisted_qc_round = self
            .io
            .storage
            .latest_qc()
            .as_deref()
            .map_or(Round::INITIAL, QuorumCertificate::round);
        let (epoch, schedule) = self.process.folded_schedule();
        let actions = self.replica.attach_signer(
            self.now,
            validator,
            record,
            persisted_qc_round,
            schedule,
            epoch,
        );
        self.drain_actions(actions);
        self.attached.push(validator);
    }

    /// Detach `validator` from the replica: close its gate, waiting out a
    /// signature already started, so nothing it queued signs after this
    /// returns. The replica keeps following the chain. Returns whether
    /// the validator was attached.
    pub fn detach_signer(&mut self, validator: ValidatorId) -> bool {
        let Some(attached) = self.signers.remove(&validator) else {
            return false;
        };
        attached.gate.close_and_wait();
        self.replica.detach_signer(validator);
        true
    }

    #[allow(clippy::too_many_lines)] // single dispatch over ShardScopedInput variants
    fn dispatch_input(&mut self, input: ShardScopedInput) {
        match input {
            // ── Transaction validation pipeline ────────────────────────
            ShardScopedInput::TransactionGossipReceived { tx } => {
                self.handle_gossip_received_tx_for_validation(tx);
            }
            ShardScopedInput::AdmitTransaction { tx } => {
                self.handle_admit_transaction(tx);
            }
            ShardScopedInput::AdmitAndGossipTransaction { tx, touched_shards } => {
                self.handle_admit_and_gossip_transaction(tx, &touched_shards);
            }
            ShardScopedInput::GossipTransaction { tx, touched_shards } => {
                self.handle_gossip_transaction(&tx, &touched_shards);
            }
            ShardScopedInput::TransactionValidated { tx } => {
                self.handle_transaction_validated(tx);
            }
            ShardScopedInput::TransactionValidationsFailed { hashes } => {
                self.handle_transaction_validations_failed(&hashes);
            }
            ShardScopedInput::ProposalReceived { proposal } => {
                self.handle_proposal_received(*proposal);
            }
            ShardScopedInput::ProposalFetched { proposal } => {
                self.handle_proposal_fetched(*proposal);
            }
            ShardScopedInput::Protocol(event) => match *event {
                ProtocolEvent::BlockPersisted { height, .. } => self.handle_block_persisted(height),
                persisted @ ProtocolEvent::BeaconBlockPersisted { .. } => {
                    self.handle_beacon_block_persisted(persisted);
                }
                restored @ ProtocolEvent::CommittedStateRestored { .. } => {
                    self.handle_committed_state_restored(restored);
                }
                ProtocolEvent::TransactionsReceived { transactions } => {
                    self.handle_transactions_received(transactions);
                }
                other => self.handle_protocol_passthrough(other),
            },

            // ── Sync protocol ──────────────────────────────────────────
            ShardScopedInput::BlockSyncResponseReceived { height, block } => {
                self.handle_block_sync_response_received(height, block);
            }
            ShardScopedInput::BlockSyncFetchFailed { height, kind } => {
                self.handle_block_sync_fetch_failed(height, kind);
            }
            ShardScopedInput::BlockSyncBelowFloor { height, floor } => {
                self.handle_block_sync_below_floor(height, floor);
            }
            ShardScopedInput::SyncBlockValidated { height, certified } => {
                self.handle_sync_block_validated(height, *certified);
            }
            ShardScopedInput::SyncBlockValidationFailed { height, reason } => {
                self.handle_sync_block_validation_failed(height, reason);
            }
            ShardScopedInput::RemoteHeadersResponseReceived {
                source_shard,
                from_height,
                count,
                headers,
                floor,
            } => {
                self.handle_remote_headers_response_received(
                    source_shard,
                    from_height,
                    count,
                    headers,
                    floor,
                );
            }
            ShardScopedInput::RemoteHeadersFetchFailed {
                source_shard,
                from_height,
                count,
                kind,
            } => {
                self.handle_remote_headers_fetch_failed(source_shard, from_height, count, kind);
            }
            ShardScopedInput::CommitProofResponseReceived { headers } => {
                self.handle_commit_proof_response_received(headers);
            }

            // ── Fetch protocol ─────────────────────────────────────────
            ShardScopedInput::FetchFailed(ids) => self.release_fetch(ids, Release::Failed),
            ShardScopedInput::FetchUnroutable(ids) => self.release_fetch(ids, Release::Unroutable),
            ShardScopedInput::FetchFulfilled(ids) => self.release_fetch(ids, Release::Admitted),
            ShardScopedInput::TransactionsFetched { batch } => {
                self.handle_fetched_txs_for_validation(batch);
            }
            ShardScopedInput::RecordsWanted { wanted } => {
                self.defer_for_records(wanted);
            }
            ShardScopedInput::RecordsArrived { arrived } => self.release_deferred(&arrived),

            // ── Certified header (gossip → signature verify → state machine) ──
            ShardScopedInput::CommittedBlockGossipReceived {
                certified_header,
                sender,
                public_key,
                sender_signature,
            } => self.handle_committed_block_gossip_received(
                certified_header,
                sender,
                public_key,
                sender_signature,
            ),

            // ── Shard fork proof (self-authenticating gossip → verify) ──
            ShardScopedInput::ShardForkProofGossipReceived { proof } => {
                self.handle_shard_fork_proof_gossip_received(&proof);
            }

            // ── Periodic fetch / sync tick ─────────────────────────────
            ShardScopedInput::FetchTick => self.handle_fetch_tick(),

            // ── QC-only commit prep callbacks ──────────────────────────
            ShardScopedInput::QcOnlyCommitPrepared {
                certified,
                source,
                witness,
                committee_anchor,
            } => {
                self.handle_qc_only_commit_prepared(certified, source, witness, committee_anchor);
            }
            ShardScopedInput::QcOnlyCommitDiverged(div) => {
                self.handle_qc_only_commit_diverged(&div);
            }
            ShardScopedInput::QcOnlyCommitWrittenPast {
                block_height,
                block_hash,
            } => {
                self.handle_qc_only_commit_written_past(block_height, block_hash);
            }
        }
    }

    /// Feed a shard-scoped protocol event to the replica at the shard's
    /// cached `now` and dispatch what it emits.
    pub(crate) fn dispatch_event(&mut self, event: ProtocolEvent) {
        // A block this node commits is one it must run, so the code its
        // members name is wanted here. Admission asked for whatever it
        // could not derive; this asks for what it derived and cannot yet
        // run — a node holding the metadata but not the compiled code,
        // and a node that synced past the admission that would have
        // asked, both reach a committed member the same way.
        //
        // A transaction that routes nowhere here names no code to ask
        // for: what it runs is behind the records it names, so those are
        // what this asks the host for, and the code follows once they
        // seat a derivation.
        if let ProtocolEvent::BlockCommitted { certified, .. } = &event {
            self.io
                .block_commit
                .note_broadcast(certified.block().height());
            let mut packages: Vec<Hash> = Vec::new();
            let mut records: Vec<Address> = Vec::new();
            for tx in certified.block().transactions().iter() {
                let tx = tx.as_unverified();
                if tx.is_routed() {
                    packages.extend(tx.packages().iter().copied());
                } else if let Some(wanted) = self.unrouted_wants(tx) {
                    records.extend(wanted.instances);
                    packages.extend(wanted.packages);
                }
            }
            if !records.is_empty() {
                self.fetch_instance_records(records);
            }
            if !packages.is_empty() {
                self.fetch_wanted_packages(packages);
            }
        }
        let actions = self.replica.handle(self.now, event);
        self.forget_untracked_remote_header_scopes();
        self.drain_actions(actions);
    }

    /// Dispatch the actions the replica emitted: bump the step's action
    /// counter, process each one, and flush pending block commits at the
    /// tail.
    pub(crate) fn drain_actions(&mut self, actions: Vec<Action>) {
        self.report_to_beacon();
        self.actions_generated += actions.len();
        for action in actions {
            self.process_action(action);
        }
        self.flush_block_commits();
    }

    /// Send what the replica's last events reported to the beacon to the
    /// host's beacon loop, under this loop's registration.
    fn report_to_beacon(&mut self) {
        let chain = self.chain;
        for input in self.replica.take_beacon_inputs() {
            let _ = self
                .process
                .beacon_event_sender
                .send(HostEvent::Beacon(BeaconScopedInput::Shard { chain, input }));
        }
    }

    /// Set this shard's cached wall-clock time. Production calls this
    /// from the shard's pinned thread; sim drives every hosted shard's
    /// time via [`NodeHost::set_time`].
    ///
    /// [`NodeHost::set_time`]: crate::host::NodeHost::set_time
    pub const fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
    }

    /// Install `genesis` on the replica and commit it through
    /// the normal pipeline, pre-spawn: a split child's flip with the
    /// deterministic [`Block::split_child_genesis`], or a fresh store on
    /// a never-crossed genesis shard with its [`network_genesis_block`].
    /// The store already holds the genesis state at the genesis version, so
    /// the commit's genesis arm re-records that height.
    ///
    /// Returns the timer ops the genesis commit produced — chiefly the
    /// consensus pacemaker's [`TimerId::ViewChange`] arm. The caller spawns
    /// the loop after this returns, so it must hand these back as the loop's
    /// initial timer ops; otherwise the first `run_step` clears them and the
    /// shard never arms its pacemaker.
    pub fn install_genesis(&mut self, genesis: &Block) -> Vec<TimerOp> {
        let certified = Arc::new(Verified::<CertifiedBlock>::genesis_certified(
            genesis.clone(),
        ));
        let actions =
            self.replica
                .initialize_genesis(self.now, genesis, self.genesis_bytes(genesis));
        self.drain_actions(actions);
        // A genesis block has no parent to anchor its committee on; its own
        // anchor is the chain origin's, the committee anchor of block one.
        let committee_anchor = genesis.header().parent_qc().weighted_timestamp();
        self.step(ShardScopedInput::Protocol(Box::new(
            ProtocolEvent::BlockCommitted {
                certified,
                committee_anchor,
            },
        )));

        self.seed_genesis_standing_answers(genesis);
        std::mem::take(&mut self.pending_timer_ops)
    }

    /// Resume a shard's consensus from its recovered committed state — a
    /// store a restarted host kept, a retained rejoin or a snap-synced
    /// join; the non-genesis counterpart of [`Self::install_genesis`].
    /// Feeds the replica the committed-state restore, which arms the
    /// pacemaker and cleanup timers and latches a proposal attempt. A
    /// replica on a live shard would pick those up from the committee's
    /// gossip, but one on a quiet chain — a halt recovery's fresh
    /// committee — hears nothing, so without this it never proposes or
    /// times out.
    ///
    /// Returns the timer ops under the same caller contract as
    /// [`Self::install_genesis`].
    pub fn resume_committed(&mut self, recovered: &RecoveredState) -> Vec<TimerOp> {
        self.step(ShardScopedInput::Protocol(Box::new(
            committed_state_restored(recovered),
        )));
        std::mem::take(&mut self.pending_timer_ops)
    }

    /// Seed the replica's answer count at `genesis` with one whole read
    /// of the genesis store, which nothing else writes yet, and start
    /// the follow from it.
    pub(crate) fn seed_genesis_standing_answers(&mut self, genesis: &Block) {
        let under = shard_prefix_path(self.shard);
        let at = (genesis.height(), genesis.hash());
        let follow = AnswerFollow::whole(&self.io.pending_chain, at, &under);
        let count = follow.count().clone();
        self.answer_follow = Some(follow);
        self.replica.seed_standing_answers(genesis.height(), count);
    }

    /// The genesis store's committed substate byte total. Every install
    /// records it with the genesis marker, so a store without it is
    /// corrupt.
    pub(crate) fn genesis_bytes(&self, genesis: &Block) -> u64 {
        self.io
            .storage
            .substate_bytes_at(genesis.height())
            .expect("an installed genesis records its byte total")
    }

    /// Process one [`ShardScopedInput`] end-to-end: clear per-step
    /// scratch, dispatch the input (which also refreshes this shard's
    /// `FetchTick` timer), then drain accumulated outputs.
    ///
    /// Production's per-shard pinned thread calls this; sim still goes
    /// through [`NodeHost::step`] for the global event queue.
    ///
    /// [`NodeHost::step`]: crate::host::NodeHost::step
    pub fn run_step(&mut self, input: ShardScopedInput) -> StepOutput {
        self.clear_scratch();
        self.step(input);
        self.take_output()
    }

    /// Clear per-step scratch so the next step's drained output reflects
    /// only that step. Called by both this loop's [`Self::run_step`] and the
    /// whole-host [`NodeHost::step`](crate::host::NodeHost::step) before
    /// dispatch; centralizing it keeps the two drivers' scratch contract in
    /// one place.
    pub(crate) fn clear_scratch(&mut self) {
        self.pending_timer_ops.clear();
        self.emitted_statuses.clear();
        self.actions_generated = 0;
        self.attached.clear();
        self.reseat = false;
    }

    /// Drain this step's accumulated scratch into a [`StepOutput`]. The
    /// counterpart to [`Self::clear_scratch`]; both drivers drain through
    /// here so the scratch field set lives in one place.
    pub(crate) fn take_output(&mut self) -> StepOutput {
        StepOutput {
            emitted_statuses: std::mem::take(&mut self.emitted_statuses),
            actions_generated: std::mem::replace(&mut self.actions_generated, 0),
            timer_ops: std::mem::take(&mut self.pending_timer_ops),
            participation_changes: Vec::new(),
            attached: std::mem::take(&mut self.attached),
            reseats: std::mem::take(&mut self.reseat)
                .then_some(self.shard)
                .into_iter()
                .collect(),
        }
    }

    /// Flush this shard's batch accumulators whose deadlines have
    /// expired at `now`.
    pub fn flush_expired_batches(&mut self, now: LocalTimestamp) {
        if self.io.mempool.validation_batch.is_expired(now) {
            self.flush_validation_batch();
        }
        self.sweep_deferred_records(now);
        if self.io.consensus.certified_header_batch.is_expired(now) {
            self.flush_certified_header_verifications();
        }
        let expired_dsts: Vec<ShardId> = self
            .io
            .mempool
            .outbound_gossip_batches
            .iter()
            .filter_map(|(dst, batch)| batch.is_expired(now).then_some(*dst))
            .collect();
        for dst in expired_dsts {
            self.flush_tx_gossip_batch(dst);
        }
    }

    /// Flush every pending batch on this shard regardless of deadline, as
    /// the shard's loop is torn down.
    pub(crate) fn flush_all_batches(&mut self) {
        self.flush_block_commits();
        self.flush_validation_batch();
        self.flush_certified_header_verifications();
        let dsts: Vec<ShardId> = self
            .io
            .mempool
            .outbound_gossip_batches
            .keys()
            .copied()
            .collect();
        for dst in dsts {
            self.flush_tx_gossip_batch(dst);
        }
    }

    /// Nearest batch deadline on this shard, if any — the production
    /// loop uses it to bound `recv_timeout` so the per-shard wake-up
    /// fires when its earliest batch expires.
    #[must_use]
    pub fn nearest_batch_deadline(&self) -> Option<LocalTimestamp> {
        [
            self.io.mempool.validation_batch.deadline(),
            self.io.consensus.certified_header_batch.deadline(),
        ]
        .into_iter()
        .chain(
            self.io
                .mempool
                .outbound_gossip_batches
                .values()
                .map(BatchAccumulator::deadline),
        )
        .flatten()
        .min()
    }
}

/// The committed-state restore for a recovered store — the one event both
/// resume paths feed ([`ShardLoop::resume_committed`] pre-spawn on the
/// pinned loop, [`NodeHost::resume_shard_committed`] through the host
/// step), so what "resuming from recovered state" means is written once.
///
/// [`NodeHost::resume_shard_committed`]: crate::host::NodeHost::resume_shard_committed
pub(crate) fn committed_state_restored(recovered: &RecoveredState) -> ProtocolEvent {
    ProtocolEvent::CommittedStateRestored {
        height: recovered.committed_height,
        hash: recovered.committed_hash,
        qc: recovered.latest_qc.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Arc;

    use crossbeam::channel::Receiver;
    use hyperscale_core::{Action, CommitSource, Gate, ProtocolEvent, StateMachine};
    use hyperscale_dispatch_sync::{DeferredJobs, ProcessingTimes, SyncDispatch};
    use hyperscale_network::HandlerRegistry;
    use hyperscale_network_memory::{PendingRequest, SimNetworkAdapter};
    use hyperscale_storage::{
        ChainEntry, ChainWrites, GenesisCommit, MemberInputs, ParentAnchor, SafeVoteRegisterStore,
        ShardChainReader, ShardChainWriter, SubstateStore,
    };
    use hyperscale_types::network::request::GetRemoteHeadersRequest;
    use hyperscale_types::test_utils::make_live_block;
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash,
        BlockHeader, BlockHeaderParts, BlockHeight, CertifiedBlock, CertifiedBlockHeader,
        ChainOrigin, Epoch, FrontierInputs, LocalTimestamp, ProposerTimestamp, QuorumCertificate,
        Round, SafeVoteRegisters, SettledWrites, ShardAnchor, ShardId, SignerBitfield, StateRoot,
        SweepFrontier, TopologySchedule, ValidatorId, Verified, VotePosition, WeightedTimestamp,
    };

    use crate::shard::cross_shard::RemoteHeaderSyncInput;
    use crate::shard::test_host::{Fixture, Host, Loop, SHARD, loop_of};
    use crate::shard::{BeaconScopedInput, HostEvent, ThreadShardLoop};

    /// A chain of empty blocks a loop commits one at a time, each
    /// prepared over the one before it.
    struct Chain {
        tip: BlockHash,
        height: BlockHeight,
        root: StateRoot,
    }

    impl Chain {
        fn on(shard_loop: &Loop) -> Self {
            let (height, tip) = shard_loop.io.storage.committed_head();
            Self {
                tip: tip.unwrap_or(BlockHash::ZERO),
                height,
                root: shard_loop.io.storage.state_root(),
            }
        }

        /// Commit the next block through the loop's replica, as its
        /// coordinator does on a certified two-chain.
        fn commit_next(&mut self, shard_loop: &mut Loop) {
            let height = self.height.next();
            let stamp = WeightedTimestamp::from_millis(height.inner());
            let (certified, root) = self.prepare_next(shard_loop, Round::new(height.inner()));
            let hash = certified.block().hash();
            shard_loop.drain_actions(vec![Action::CommitBlock {
                certified,
                source: CommitSource::Aggregator,
                witness: BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
                committee_anchor: stamp,
            }]);
            (self.tip, self.height, self.root) = (hash, height, root);
        }

        /// Prepare the next block over the tip in the loop's pending chain,
        /// certified at `round`, and hand it back with its state root,
        /// without committing it.
        fn prepare_next(
            &self,
            shard_loop: &Loop,
            round: Round,
        ) -> (Arc<Verified<CertifiedBlock>>, StateRoot) {
            let height = self.height.next();
            let stamp = WeightedTimestamp::from_millis(height.inner());
            let quorum_certificate = |hash, at: BlockHeight, parent, round| {
                QuorumCertificate::new(
                    hash,
                    SHARD,
                    at,
                    parent,
                    round,
                    SignerBitfield::empty(),
                    AggregateSignature::ZERO,
                    stamp,
                )
            };
            let mut block = make_live_block(
                SHARD,
                height,
                0,
                ValidatorId::new(0),
                Vec::new(),
                Vec::new(),
            );
            if let Block::Live { header, .. } = &mut block {
                *header = BlockHeader::new(BlockHeaderParts {
                    shard_id: SHARD,
                    height,
                    parent_block_hash: self.tip,
                    parent_qc: quorum_certificate(
                        self.tip,
                        self.height,
                        BlockHash::ZERO,
                        Round::new(self.height.inner()),
                    )
                    .into(),
                    timestamp: ProposerTimestamp::from_millis(height.inner()),
                    round: Round::new(height.inner()),
                    ..Default::default()
                });
            }
            let hash = block.hash();
            let view = shard_loop.io.pending_chain.view_at(self.tip, self.height);
            let (root, jmt_snapshot, prepared) = view.base().prepare_block_commit(
                ParentAnchor {
                    state_root: self.root,
                    height: self.height,
                    state: &view.snapshot(),
                    pending: view.pending_snapshots(),
                    base_reads: None,
                },
                &[],
                ChainWrites {
                    creations: &[],
                    removals: &[],
                    sweep_frontier: SweepFrontier::ZERO,
                    frontier: &FrontierInputs::still(SHARD),
                    state_claims: &[],
                    members: &MemberInputs::of(&block, FrontierInputs::still(SHARD).windows),
                },
                height,
            );
            shard_loop.io.pending_chain.insert(
                hash,
                ChainEntry {
                    parent_block_hash: self.tip,
                    height,
                    settled_txs: Vec::new(),
                    jmt_snapshot,
                    certified_block: None,
                },
            );
            shard_loop
                .io
                .block_commit
                .prepared_commits_handle()
                .lock()
                .unwrap()
                .insert(hash, (height, prepared));
            let qc =
                Verified::new_unchecked_for_test(quorum_certificate(hash, height, self.tip, round));
            let certified = Arc::new(Verified::new_unchecked_for_test(
                CertifiedBlock::new_unchecked(block, qc),
            ));
            (certified, root)
        }
    }

    /// A disk one flush behind its loop: what each round's commit pushed
    /// back to the loop reaches it only after the next round's commit.
    struct LaggingDisk {
        events: Receiver<HostEvent>,
        unacknowledged: VecDeque<Vec<HostEvent>>,
    }

    impl LaggingDisk {
        fn new(events: Receiver<HostEvent>) -> Self {
            Self {
                events,
                unacknowledged: VecDeque::new(),
            }
        }

        /// Hold back what the loop pushed this round and deliver the
        /// round before's.
        fn turn(&mut self, host: &mut Host) {
            self.unacknowledged
                .push_back(self.events.try_iter().collect());
            if self.unacknowledged.len() > 1 {
                for event in self.unacknowledged.pop_front().into_iter().flatten() {
                    let _ = host.step(event);
                }
            }
        }

        /// Deliver everything outstanding, and whatever that pushes.
        fn settle(&mut self, host: &mut Host) {
            loop {
                self.unacknowledged
                    .push_back(self.events.try_iter().collect());
                let events: Vec<HostEvent> = self.unacknowledged.drain(..).flatten().collect();
                if events.is_empty() {
                    return;
                }
                for event in events {
                    let _ = host.step(event);
                }
            }
        }
    }

    /// The last height the replica's execution folded off the commit
    /// stream.
    fn folded(host: &mut Host) -> BlockHeight {
        loop_of(host)
            .replica
            .execution_coordinator()
            .committed_height()
    }

    /// A signer attached to an open loop whose chain commits without pause, over
    /// a disk that never catches up with it, signs from the step that
    /// attaches it: the timeout the replica asks of it when its round
    /// times out in the next step is signed and persisted there, with the
    /// disk still behind. The replica then folds every later height with
    /// the signer attached.
    #[test]
    fn a_signer_attaches_to_a_loop_under_continuous_commits_at_once() {
        let fix = Fixture::new();
        let (mut host, events) = fix.host_with_events(BlockHeight::GENESIS);
        let mut disk = LaggingDisk::new(events);
        let shard_loop = loop_of(&mut host);
        let state_root = shard_loop
            .io
            .storage
            .install_genesis(&SettledWrites::default(), &SettledWrites::default());
        let genesis = Block::genesis(
            SHARD,
            fix.committee.validator_id(0),
            state_root,
            ChainOrigin::root(WeightedTimestamp::ZERO),
        );
        let _ = shard_loop.install_genesis(&genesis);
        shard_loop.dispatch_event(ProtocolEvent::BeaconBlockPersisted {
            epoch: Epoch::new(1),
            schedule: Arc::new(TopologySchedule::single(Arc::new(fix.topology(
                BTreeMap::from([(
                    SHARD,
                    vec![fix.committee.validator_id(0), fix.committee.validator_id(1)],
                )]),
            )))),
        });
        disk.settle(&mut host);
        let mut chain = Chain::on(loop_of(&mut host));
        for _ in 0..4 {
            chain.commit_next(loop_of(&mut host));
            disk.turn(&mut host);
        }

        let (joiner, signer) = fix.identity(1);
        let _ = host.attach_signer(SHARD, joiner, signer);
        let last_signed = |host: &mut Host| {
            loop_of(host)
                .io
                .storage
                .safe_vote_registers(joiner)
                .map(|record| record.last_voted_round)
        };
        assert_eq!(last_signed(&mut host), None);
        chain.commit_next(loop_of(&mut host));

        let shard_loop = loop_of(&mut host);
        let timed_out = LocalTimestamp::from_millis(600_000);
        shard_loop.set_time(timed_out);
        let actions = shard_loop
            .replica
            .handle(timed_out, ProtocolEvent::ViewChangeTimer);
        let asked = actions
            .iter()
            .find_map(|action| match action {
                Action::SignAndBroadcastTimeout {
                    signer, position, ..
                } if *signer == joiner => Some(position.registers.last_voted_round),
                _ => None,
            })
            .unwrap_or_else(|| panic!("the replica asks the joiner for a timeout: {actions:?}"));
        shard_loop.drain_actions(actions);
        assert_eq!(last_signed(&mut host), Some(asked), "signed at once");
        disk.turn(&mut host);

        for _ in 0..3 {
            chain.commit_next(loop_of(&mut host));
            disk.turn(&mut host);
        }
        disk.settle(&mut host);
        assert_eq!(folded(&mut host), chain.height);
    }

    /// A signer attached to a running loop locks at the QC the store
    /// persisted for its committed tip, not at a higher one the pending
    /// chain shadows it with: a certified block not yet committed can
    /// belong to a branch a pending fork recovery abandons.
    #[test]
    fn an_attached_signer_locks_at_the_persisted_qc_not_the_pending_one() {
        let fix = Fixture::new();
        let (mut host, events) = fix.host_with_events(BlockHeight::GENESIS);
        let mut disk = LaggingDisk::new(events);
        let mut chain = Chain::on(loop_of(&mut host));
        for _ in 0..3 {
            chain.commit_next(loop_of(&mut host));
        }
        disk.settle(&mut host);

        let shard_loop = loop_of(&mut host);
        let (pending, _) = chain.prepare_next(shard_loop, Round::new(50));
        shard_loop
            .io
            .pending_chain
            .attach_certified_block(pending.block().hash(), pending);
        let persisted = shard_loop
            .io
            .storage
            .latest_qc()
            .map(|qc| qc.round())
            .expect("the store persisted its tip's QC");
        let shadowed = shard_loop.io.pending_chain.latest_qc().map(|qc| qc.round());
        assert_eq!(shadowed, Some(Round::new(50)));
        assert!(persisted < Round::new(50));

        let (joiner, signer) = fix.identity(1);
        let _ = host.attach_signer(SHARD, joiner, signer);
        let position = host
            .replica(SHARD)
            .shard_coordinator()
            .position(joiner)
            .expect("the joiner is attached");
        assert_eq!(position.locked_round, persisted);
        assert_eq!(position.last_voted_round, persisted);
    }

    /// A loop on a thread of its own closes the gate of every signer
    /// attached to it as it drops, before it releases its chain, so
    /// nothing it signs leaves the host once the supervisor's join of the
    /// thread reports it torn down.
    #[test]
    fn a_loop_closes_every_gate_before_it_reports_torn_down() {
        let fix = Fixture::new();
        let (mut host, events) = fix.host_with_events(BlockHeight::GENESIS);
        let (joiner, signer) = fix.identity(1);
        let _ = host.attach_signer(SHARD, joiner, signer);
        while events.try_recv().is_ok() {}
        let (_process, mut shards, _beacon) = host.into_parts();
        let shard_loop = shards.remove(&SHARD).expect("the fixture hosts SHARD");
        let chain = shard_loop.chain;
        let gates: Vec<Arc<Gate>> = shard_loop
            .signers
            .values()
            .map(|attached| Arc::clone(&attached.gate))
            .collect();
        assert_eq!(gates.len(), 2);

        std::thread::spawn(move || drop(ThreadShardLoop::from(shard_loop)))
            .join()
            .expect("the loop's thread returns");

        for gate in &gates {
            assert!(gate.enter().is_none(), "every gate is closed");
        }
        assert!(
            events.try_iter().any(|event| matches!(
                event,
                HostEvent::Beacon(BeaconScopedInput::Deregister(released)) if released == chain
            )),
            "the chain is released",
        );
    }

    /// A timeout `signer` signs at `round`, its position advanced to it.
    fn timeout_at(signer: ValidatorId, round: u64) -> Action {
        Action::SignAndBroadcastTimeout {
            round: Round::new(round),
            high_qc: QuorumCertificate::genesis(SHARD, ChainOrigin::root(WeightedTimestamp::ZERO)),
            high_tc: None,
            recipients: Vec::new(),
            position: VotePosition {
                registers: SafeVoteRegisters {
                    last_voted_round: Round::new(round),
                    ..SafeVoteRegisters::default()
                },
                justification: Vec::new(),
            },
            signer,
        }
    }

    /// A signature queued on the pool under one attachment of a
    /// validator, and run after the loop detached it and attached it
    /// again, signs nothing and persists nothing: it holds the gate the
    /// detach closed. The new attachment's own signatures go out.
    #[test]
    fn a_task_queued_before_a_detach_does_not_sign_after_a_reattach() {
        let fix = Fixture::new();
        let jobs = Arc::new(DeferredJobs::new(ProcessingTimes::INSTANT, 7));
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
        let (mut host, _events) = fix.host_through_network(
            SimNetworkAdapter::new(registry),
            SyncDispatch::deferred(Arc::clone(&jobs)),
        );
        let run_queued = || {
            for (_, job) in jobs.take() {
                job();
            }
        };
        let (validator, signer) = fix.identity(1);
        let _ = host.attach_signer(SHARD, validator, Arc::clone(&signer));
        run_queued();

        loop_of(&mut host).drain_actions(vec![timeout_at(validator, 5)]);
        let queued = jobs.take();
        assert!(!queued.is_empty(), "the timeout is queued on the pool");

        assert!(host.detach_signer(SHARD, validator));
        let _ = host.attach_signer(SHARD, validator, signer);
        run_queued();
        for (_, job) in queued {
            job();
        }
        let record = |host: &mut Host| {
            loop_of(host)
                .io
                .storage
                .safe_vote_registers(validator)
                .map(|record| record.last_voted_round)
        };
        assert_eq!(record(&mut host), None, "the queued timeout persisted");

        loop_of(&mut host).drain_actions(vec![timeout_at(validator, 6)]);
        run_queued();
        assert_eq!(record(&mut host), Some(Round::new(6)));
    }

    /// The shard beside `SHARD` in the fixture's two-leaf trie, whose
    /// headers the replica tracks.
    const REMOTE: ShardId = ShardId::leaf(1, 1);

    /// A one-window schedule tracking `REMOTE`, seated with the committee's
    /// last two members, at an attested boundary of `boundary`.
    fn tracking_remote(fix: &Fixture, boundary: BlockHeight) -> Arc<TopologySchedule> {
        let snapshot = fix
            .topology(BTreeMap::from([
                (
                    SHARD,
                    vec![fix.committee.validator_id(0), fix.committee.validator_id(1)],
                ),
                (
                    REMOTE,
                    vec![fix.committee.validator_id(2), fix.committee.validator_id(3)],
                ),
            ]))
            .with_boundaries(BTreeMap::from([(
                REMOTE,
                ShardAnchor {
                    state_root: StateRoot::ZERO,
                    block_hash: BlockHash::ZERO,
                    height: boundary,
                    weighted_timestamp: WeightedTimestamp::ZERO,
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    terminal_settled_txs: None,
                    handoff_complete: None,
                    terminal_epoch: None,
                },
            )]));
        Arc::new(TopologySchedule::single(Arc::new(snapshot)))
    }

    /// A one-window schedule in which `REMOTE` has split, so the replica
    /// tracks it no longer.
    fn untracking_remote(fix: &Fixture) -> Arc<TopologySchedule> {
        let (left, right) = REMOTE.children();
        let snapshot = fix.topology_over_leaves(BTreeMap::from([
            (
                SHARD,
                vec![fix.committee.validator_id(0), fix.committee.validator_id(1)],
            ),
            (left, vec![fix.committee.validator_id(2)]),
            (right, vec![fix.committee.validator_id(3)]),
        ]));
        Arc::new(TopologySchedule::single(Arc::new(snapshot)))
    }

    /// Install `schedule` on the loop at `epoch`, then have the replica
    /// reconcile what it tracks against it and raise every tracked shard's
    /// sync target, as a block sync completing does.
    fn persist_and_flush(host: &mut Host, epoch: u64, schedule: Arc<TopologySchedule>) {
        let shard_loop = loop_of(host);
        shard_loop.dispatch_event(ProtocolEvent::BeaconBlockPersisted {
            epoch: Epoch::new(epoch),
            schedule,
        });
        shard_loop.dispatch_event(ProtocolEvent::BlockSyncComplete {
            height: BlockHeight::GENESIS,
        });
    }

    /// The heights the loop asked `REMOTE`'s committee for headers from.
    fn remote_fetches(host: &Host) -> Vec<BlockHeight> {
        host.network()
            .drain_pending_requests()
            .iter()
            .filter_map(PendingRequest::request::<GetRemoteHeadersRequest>)
            .filter(|request| request.source_shard == REMOTE)
            .map(|request| request.from_height)
            .collect()
    }

    /// A host on the fixture's network at the epoch-1 schedule, tracking
    /// `REMOTE` from genesis with its requests drained, beside the channel
    /// its loop pushes its own events into.
    fn host_tracking_remote(fix: &Fixture) -> (Host, Receiver<HostEvent>) {
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
        let (mut host, events) =
            fix.host_through_network(SimNetworkAdapter::new(registry), SyncDispatch::new());
        persist_and_flush(&mut host, 1, tracking_remote(fix, BlockHeight::GENESIS));
        let _ = remote_fetches(&host);
        (host, events)
    }

    /// A shard the replica stops tracking and tracks again from a lower
    /// anchor syncs from that anchor: its scope went with the untrack, so
    /// the scope the re-track starts is not held at the height the old one
    /// reached.
    #[test]
    fn a_shard_tracked_again_syncs_from_its_new_anchor() {
        let fix = Fixture::new();
        let (mut host, _events) = host_tracking_remote(&fix);
        let _ = loop_of(&mut host).io.cross_shard.remote_header_sync.handle(
            RemoteHeaderSyncInput::Admitted {
                scope: REMOTE,
                height: BlockHeight::new(50),
            },
        );

        persist_and_flush(&mut host, 2, untracking_remote(&fix));
        assert!(remote_fetches(&host).is_empty());

        persist_and_flush(&mut host, 3, tracking_remote(&fix, BlockHeight::new(10)));
        let fetches = remote_fetches(&host);
        assert_eq!(fetches.first(), Some(&BlockHeight::new(11)), "{fetches:?}");
    }

    /// A shard tracked again from its anchor starts its scope on the first
    /// header it admits from the shard's live tip, and fetches the gap
    /// between them at once rather than waiting out the liveness probe.
    #[test]
    fn a_shard_tracked_again_fetches_up_to_its_first_header_at_once() {
        let fix = Fixture::new();
        let (mut host, events) = host_tracking_remote(&fix);
        persist_and_flush(&mut host, 2, untracking_remote(&fix));
        let _ = remote_fetches(&host);

        loop_of(&mut host).dispatch_event(ProtocolEvent::BeaconBlockPersisted {
            epoch: Epoch::new(3),
            schedule: tracking_remote(&fix, BlockHeight::new(10)),
        });
        let mut chain = Chain::on(loop_of(&mut host));
        chain.commit_next(loop_of(&mut host));
        for event in events.try_iter() {
            let _ = host.step(event);
        }
        assert_eq!(
            loop_of(&mut host)
                .replica
                .remote_headers_coordinator()
                .verified_frontier(REMOTE),
            Some(BlockHeight::new(10)),
            "the commit tracks the shard again at its anchor",
        );
        assert!(remote_fetches(&host).is_empty());

        let tip = BlockHeight::new(40);
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: REMOTE,
            height: tip,
            round: Round::new(tip.inner()),
            ..Default::default()
        });
        let qc = QuorumCertificate::new(
            header.hash(),
            REMOTE,
            tip,
            BlockHash::ZERO,
            Round::new(tip.inner()),
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        let certified = CertifiedBlockHeader::new(header, qc);
        loop_of(&mut host).dispatch_event(ProtocolEvent::RemoteHeaderQcVerified {
            certified_header: Arc::new(certified.clone()),
            sender: fix.committee.validator_id(2),
            result: Box::new(Ok(Verified::new_unchecked_for_test(certified))),
        });
        let fetches = remote_fetches(&host);
        assert_eq!(fetches.first(), Some(&BlockHeight::new(11)), "{fetches:?}");
    }

    /// An execution vote for a tick leader attached to the same replica is
    /// fed back to the replica and sent over no network, so no fault there
    /// can drop it.
    #[test]
    fn an_execution_vote_for_a_co_hosted_leader_is_fed_back_not_sent() {
        use hyperscale_types::{GlobalReceiptRoot, TickId};

        use crate::shard::ShardScopedInput;

        let fix = Fixture::new();
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
        let (mut host, events) =
            fix.host_through_network(SimNetworkAdapter::new(registry), SyncDispatch::new());
        let (leader, signer) = fix.identity(1);
        let _ = host.attach_signer(SHARD, leader, signer);
        while events.try_recv().is_ok() {}
        let _ = host.network().drain_outbox();
        let _ = host.network().drain_pending_notifications();

        let voter = fix.committee.validator_id(0);
        loop_of(&mut host).drain_actions(vec![Action::SignAndSendExecutionVote {
            block_hash: BlockHash::ZERO,
            vote_anchor_ts: WeightedTimestamp::ZERO,
            tick_id: TickId::new(SHARD, BlockHeight::new(1)),
            global_receipt_root: GlobalReceiptRoot::ZERO,
            tx_outcomes: Vec::new(),
            recipients: Vec::new(),
            local_recipient: true,
            signer: voter,
        }]);

        assert!(
            events.try_iter().any(|event| matches!(
                event,
                HostEvent::Shard(shard, ShardScopedInput::Protocol(event))
                    if shard == SHARD && matches!(
                        &*event,
                        ProtocolEvent::ExecutionVoteReceived { vote } if vote.validator() == voter
                    )
            )),
            "the vote is fed back to the replica",
        );
        assert!(host.network().drain_outbox().is_empty());
        assert!(host.network().drain_pending_notifications().is_empty());
    }
    /// The answer to one of the loop's own fetches reaches it on the
    /// internal lane however full the network lane is, so the fetch it
    /// answers is released rather than stranded behind peer traffic.
    #[test]
    fn a_fetch_answer_is_released_past_a_full_network_lane() {
        use crossbeam::channel::{bounded, unbounded};
        use hyperscale_core::FetchIds;

        use crate::fetch::{FetchReply, ShardReply};
        use crate::shard::{ShardInbox, ShardScopedInput};

        let fix = Fixture::new();
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
        let (internal_tx, internal) = unbounded();
        let (network_tx, _network) = bounded(1);
        let (beacon_tx, _beacon) = unbounded();
        let mut host = fix.host_with_inbox(
            registry,
            beacon_tx,
            ShardInbox::new(internal_tx, network_tx.clone()),
        );
        network_tx
            .try_send(HostEvent::shard(SHARD, ShardScopedInput::FetchTick))
            .expect("the lane has room for one");
        while internal.try_recv().is_ok() {}

        let sender = loop_of(&mut host).event_sender().clone();
        assert!(
            !sender.same_channel(&network_tx),
            "the loop's own sender is not its network lane",
        );
        let ids = FetchIds::Transactions(Vec::new());
        ShardReply {
            shard: SHARD,
            sender,
        }
        .answered(ids.clone(), ProtocolEvent::CleanupTimer);
        assert!(
            internal.try_iter().any(|event| matches!(
                event,
                HostEvent::Shard(_, ShardScopedInput::FetchFulfilled(fulfilled)) if fulfilled == ids
            )),
            "the answered fetch is released",
        );
    }
}
