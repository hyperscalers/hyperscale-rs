//! Per-host driver for shard-less vnodes: the beacon-follower pool.
//!
//! A [`PoolLoop`] drives the vnodes a host runs with `shard: None` — logical
//! nodes that follow the beacon chain (adopt committed beacon blocks, track
//! topology, surface their own seat triggers) but run no shard consensus. It is
//! the lightweight sibling of [`ShardLoop`](crate::shard::ShardLoop): a
//! `Vec<Vnode>` plus a cloned `Arc<ProcessIo>` and per-step scratch — no
//! `ShardIo`, no batch accumulators, no per-payload fetches.
//!
//! A follower's entire action set is handled **inline** — loop effects
//! directly, beacon-owned delegated actions through the same
//! [`hyperscale_beacon::action_handlers`] a seated vnode's dispatch runs,
//! built over the storage-free `BeaconActionContext` (the full
//! `ActionContext` needs a `PendingChain` a shard-less host has no storage
//! for). The work is cheap: signature checks, signing, broadcasts, and
//! adoption touching process-shared state (the beacon commit dedup, the
//! topology `ArcSwap`). Because a pooled vnode no-ops
//! `BeaconBlockPersisted` (it has no shard coordinators to replay into), the
//! whole `received → verify → adopt → commit` cascade runs to quiescence
//! within one `PoolLoop::dispatch_event`, with no event-channel round trip.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyperscale_beacon::action_handlers::handle_action as handle_beacon_action;
use hyperscale_core::{
    Action, ActionOwner, BeaconActionContext, ParticipationChange, ProtocolEvent, StateMachine,
};
use hyperscale_dispatch::Dispatch;
use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::beacon::GetBeaconBlockRequest;
use hyperscale_types::network::response::beacon::GetBeaconBlockResponse;
use hyperscale_types::{
    BeaconProposal, CertifiedBeaconBlock, Epoch, LocalTimestamp, ShardId, ValidatorId, Verifiable,
    Verified,
};
use tracing::{trace, warn};

use crate::beacon::{self, BeaconBlockSync, BeaconSyncSink, beacon_block_sync_config};
use crate::event::{HostEvent, PoolScopedInput, classify_fetch_error};
use crate::process::ProcessIo;
use crate::shard::{StepOutput, TimerOp};
use crate::vnode::Vnode;

/// Cadence at which a syncing pool retries deferred beacon-block fetches.
///
/// An idle pool never fires it: the production thread's `select!` just
/// re-checks shutdown each interval, and the simulation schedules no tick.
pub const POOL_FETCH_TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Active driver for a host's shard-less, beacon-following vnodes.
pub struct PoolLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    /// Process-scoped resources shared with every other driver on the host:
    /// beacon storage, the beacon-commit dedup gate, the topology `ArcSwap`.
    pub(crate) process: Arc<ProcessIo<S, N, D>>,

    /// The shard-less vnodes this host follows the beacon with. Driven in order
    /// each step; each independently folds the same committed beacon blocks.
    pub vnodes: Vec<Vnode>,

    /// Cached wall-clock time, set by [`NodeHost::set_time`](crate::host::NodeHost::set_time).
    now: LocalTimestamp,

    /// Per-step scratch: placement deltas emitted via
    /// `Action::ReconfigureParticipation` — the seat/drain triggers the runner
    /// acts on. Cleared at step entry, drained into the step's `StepOutput`.
    pub(crate) pending_participation_changes: Vec<ParticipationChange>,

    /// Per-step scratch: timer operations the pooled vnodes emitted,
    /// `shard: None` (a follower has no shard — the runner keys its pool
    /// timers by `TimerId` alone and routes fires back through the beacon
    /// channel). A follower is a ratify-pool voter and can be drawn onto
    /// an SPC committee, so its beacon timer chain must stay live.
    pub(crate) pending_timer_ops: Vec<TimerOp>,

    /// Per-step scratch: count of actions the pooled vnodes produced.
    pub(crate) actions_generated: usize,

    /// Beacon-block catch-up sync, scope `()`. A follower's coordinator
    /// emits `Action::StartBeaconBlockSync` when a gossiped block sits more
    /// than one epoch ahead of its tip; this FSM drives the
    /// `GetBeaconBlockRequest` fetches that close the gap, fed back through
    /// the host's beacon channel.
    beacon_block: BeaconBlockSync,
}

impl<S, N, D> PoolLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Build a pool driver over the host's shard-less vnodes. Used by
    /// `NodeHost::new` at construction and by the production supervisor when
    /// it builds a follower pool at runtime.
    ///
    /// Every follower's beacon startup timers are armed into the timer
    /// scratch here; the caller drains them to its timer table (the sim
    /// through the construction-time `drain_pending_output`, the
    /// production pool thread by re-arming at spawn).
    pub fn new(process: Arc<ProcessIo<S, N, D>>, vnodes: Vec<Vnode>) -> Self {
        let mut pool = Self {
            process,
            vnodes,
            now: LocalTimestamp::ZERO,
            pending_participation_changes: Vec::new(),
            pending_timer_ops: Vec::new(),
            actions_generated: 0,
            beacon_block: BeaconBlockSync::new(beacon_block_sync_config()),
        };
        pool.arm_startup_timers();
        pool
    }

    /// Add a follower at runtime — a validator that drained off its last
    /// shard — arming its beacon startup timers into the timer scratch for
    /// the caller to drain.
    pub(crate) fn add_vnode(&mut self, vnode: Vnode) {
        self.vnodes.push(vnode);
        self.arm_beacon_startup(self.vnodes.len() - 1);
    }

    /// Arm every follower's beacon startup timers into the timer scratch.
    /// Idempotent: re-arming replaces the pending fire at the runner's
    /// table, and the durations recompute identically from each
    /// coordinator's clock.
    fn arm_startup_timers(&mut self) {
        for vnode_idx in 0..self.vnodes.len() {
            self.arm_beacon_startup(vnode_idx);
        }
    }

    /// Re-arm every follower's beacon startup timers and drain the result —
    /// the production pool thread's spawn-time bootstrap. Replayable: the
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
        let actions = self.vnodes[vnode_idx].state.beacon_startup_actions();
        self.actions_generated += actions.len();
        let mut queue = VecDeque::new();
        for action in actions {
            self.process_action(vnode_idx, action, &mut queue);
        }
        debug_assert!(queue.is_empty(), "startup arming emits only timer sets");
    }

    /// Set the cached wall-clock time observed by `state.handle(now, _)`.
    pub const fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
    }

    /// Number of pooled vnodes.
    #[must_use]
    pub(crate) const fn len(&self) -> usize {
        self.vnodes.len()
    }

    /// Whether the pool holds no vnodes.
    #[must_use]
    pub(crate) const fn is_empty(&self) -> bool {
        self.vnodes.is_empty()
    }

    /// Clear per-step scratch. Called by [`NodeHost::step`](crate::host::NodeHost::step)
    /// before dispatch so the drained output reflects only this step.
    pub(crate) fn clear_scratch(&mut self) {
        self.pending_participation_changes.clear();
        self.pending_timer_ops.clear();
        self.actions_generated = 0;
    }

    /// Drive one pool input through every pooled vnode and return the step's
    /// output: the placement deltas the followers surfaced (the seat triggers
    /// the supervisor acts on) and their timer operations. Clears per-step
    /// scratch first, mirroring
    /// [`ShardLoop::run_step`](crate::shard::ShardLoop::run_step); used by
    /// the production pool thread, which owns the `PoolLoop` directly rather
    /// than driving it through [`NodeHost::step`](crate::host::NodeHost::step).
    pub fn run_step(&mut self, input: PoolScopedInput) -> StepOutput {
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

    /// Route a [`PoolScopedInput`] to the pooled vnodes or the catch-up
    /// sync FSM.
    pub(crate) fn dispatch_event(&mut self, input: PoolScopedInput) {
        match input {
            PoolScopedInput::Protocol(event) => self.dispatch_protocol(*event),
            PoolScopedInput::BeaconBlockSyncResponseReceived { epoch, block } => {
                beacon::on_response(self, epoch, block);
            }
            PoolScopedInput::BeaconBlockSyncFetchFailed { epoch, kind } => {
                beacon::on_fetch_failed(self, epoch, kind);
            }
            PoolScopedInput::FetchTick => beacon::on_tick(self),
        }
    }

    /// Fan a beacon [`ProtocolEvent`] across every pooled vnode, driving each
    /// one's follower cascade to quiescence.
    fn dispatch_protocol(&mut self, event: ProtocolEvent) {
        let count = self.vnodes.len();
        if count == 0 {
            return;
        }
        // Clone for every vnode except the last; the last takes ownership.
        for vnode_idx in 0..count - 1 {
            self.drive(vnode_idx, event.clone());
        }
        self.drive(count - 1, event);
    }

    /// Drive one pooled vnode: feed `event`, handle the emitted actions inline,
    /// and feed back any beacon continuation (a verify result) until the vnode
    /// stops producing them.
    fn drive(&mut self, vnode_idx: usize, event: ProtocolEvent) {
        let now = self.now;
        let mut queue = VecDeque::from([event]);
        while let Some(ev) = queue.pop_front() {
            let actions = self.vnodes[vnode_idx].state.handle(now, ev);
            self.actions_generated += actions.len();
            for action in actions {
                self.process_action(vnode_idx, action, &mut queue);
            }
        }
    }

    /// Handle one action from a beacon follower: the loop-internal effects
    /// (commit, topology, seat trigger, timer op, catch-up sync) inline,
    /// and every beacon-owned delegated action through the same
    /// [`hyperscale_beacon::action_handlers`] a seated vnode's dispatch
    /// runs — a pooled validator can sit in the ratify pool or on an SPC
    /// committee while its seat is still pending, and its votes and
    /// proposals must flow. Anything else belongs to shard consensus,
    /// which a follower never runs.
    fn process_action(
        &mut self,
        vnode_idx: usize,
        action: Action,
        queue: &mut VecDeque<ProtocolEvent>,
    ) {
        match action {
            Action::CommitBeaconBlock { block, state } => {
                let epoch = block.epoch();
                // Process-scoped dedup: the first vnode to reach this
                // `(epoch, hash)` writes to the host's beacon storage. A pooled
                // vnode no-ops `BeaconBlockPersisted`, so it isn't fed back.
                self.process
                    .beacon_commit
                    .commit(&self.process.beacon_storage, &block, &state);
                // Advance the sync FSM's committed watermark on every commit
                // (gossip or sync) so a serial catch-up unblocks the next
                // epoch's fetch and a later sync starts from current+1.
                beacon::on_admitted(self, epoch);
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
            // the runner's timer table, keyed by `TimerId` alone — no shard.
            Action::SetTimer { id, duration } => {
                self.pending_timer_ops.push(TimerOp::Set {
                    shard: None,
                    id,
                    duration,
                });
            }
            Action::CancelTimer { id } => {
                self.pending_timer_ops
                    .push(TimerOp::Cancel { shard: None, id });
            }
            // Catch-up sync: a follower fell behind a gossiped block, so drive
            // the FSM to fetch the missing epochs from a live committee.
            Action::StartBeaconBlockSync { target } => {
                beacon::start(self, target);
            }
            other if other.owner() == ActionOwner::Beacon => {
                self.run_beacon_action(vnode_idx, other, queue);
            }
            other => {
                warn!(
                    action = other.type_name(),
                    "PoolLoop: unexpected action from a beacon follower — dropping"
                );
            }
        }
    }

    /// Run one beacon-owned delegated action inline, with the same signing
    /// gates the shard dispatch applies. Handler outcomes re-enter the same
    /// vnode as continuations so the whole cascade stays synchronous.
    fn run_beacon_action(
        &self,
        vnode_idx: usize,
        action: Action,
        queue: &mut VecDeque<ProtocolEvent>,
    ) {
        let me = self.vnodes[vnode_idx].validator_id;
        // The process-level signing fences, shared with every seated vnode of
        // the same validator: one ratify signature per position, one SPC view
        // claim per epoch — a seat racing this follower's retirement cannot
        // double-sign. The pool claims views as `None`, a claimant no hosted
        // shard can alias (a single-shard network's only leaf is
        // `ShardId::ROOT`).
        if let Some(position) = action.ratify_signing_position() {
            if !self.process.allow_ratify_signing(me, position) {
                trace!(
                    validator = ?me,
                    epoch = position.0.inner(),
                    round = position.1.inner(),
                    "PoolLoop: dropping already-covered ratify vote position"
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
                "PoolLoop: dropping beacon signing action for an unclaimed view"
            );
            return;
        }

        // Handler outcomes buffer here and drain into the cascade queue
        // after the call. The beacon handlers notify synchronously — none
        // clone `notify` into a callback that outlives the action — so the
        // drain sees every outcome.
        let outcomes: Arc<Mutex<Vec<ProtocolEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&outcomes);
        let notify: Arc<dyn Fn(ProtocolEvent) + Send + Sync> = Arc::new(move |event| {
            sink.lock().expect("pool outcome sink lock").push(event);
        });
        let proposal_cache = &self.process.dispatch_handles.beacon_proposal_cache;
        let cache_beacon_proposal =
            |from: ValidatorId, epoch: Epoch, proposal: Arc<Verified<BeaconProposal>>| {
                proposal_cache.admit(from, epoch, proposal);
            };
        let vnode = &self.vnodes[vnode_idx];
        let ctx = BeaconActionContext {
            topology_snapshot: vnode.state.topology_arc(),
            me,
            ratify_registers: self.process.beacon_storage.as_ref(),
            network: &self.process.network,
            signer: &vnode.signer,
            verifier: vnode.state.beacon_coordinator().verifier().as_ref(),
            notify,
            cache_beacon_proposal: &cache_beacon_proposal,
        };
        handle_beacon_action(action, &ctx);
        drop(ctx);
        queue.extend(std::mem::take(
            &mut *outcomes.lock().expect("pool outcome sink lock"),
        ));
    }

    /// Whether a catch-up sync is in flight — actively fetching or holding
    /// epochs deferred behind a backoff. The driver ticks the pool while true
    /// and lets it idle otherwise.
    #[must_use]
    pub fn is_beacon_syncing(&self) -> bool {
        beacon::has_pending(&self.beacon_block)
    }

    /// Pick a live shard whose committee can serve the follower's beacon
    /// fetch. Every shard member holds the beacon chain, so any live leaf
    /// answers; spreading by the follower's own id keeps a host of followers
    /// from all hammering one committee.
    fn fetch_shard(&self) -> Option<ShardId> {
        let vnode = self.vnodes.first()?;
        let leaves: Vec<ShardId> = vnode
            .state
            .topology_snapshot()
            .shard_trie()
            .leaves()
            .collect();
        if leaves.is_empty() {
            return None;
        }
        let idx = usize::try_from(vnode.validator_id.inner() % leaves.len() as u64)
            .expect("modulo of leaves.len() fits usize");
        Some(leaves[idx])
    }
}

impl<S, N, D> BeaconSyncSink for PoolLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    fn beacon_fsm(&mut self) -> &mut BeaconBlockSync {
        &mut self.beacon_block
    }

    fn deliver_block(&mut self, block: Arc<Verifiable<CertifiedBeaconBlock>>) {
        // Deliver to every follower inline — each runs the verify/adopt/commit
        // cascade to quiescence within this call.
        self.dispatch_protocol(ProtocolEvent::BeaconBlockSyncReadyToApply { block });
    }

    fn dispatch_fetch(&self, epoch: Epoch) {
        let Some(shard) = self.fetch_shard() else {
            warn!("PoolLoop: no live shard to fetch beacon blocks from; deferring");
            return;
        };
        let beacon_tx = self.process.beacon_event_sender.clone();
        self.process.network.request(
            shard,
            None,
            GetBeaconBlockRequest::new(epoch),
            None,
            Box::new(
                move |result: Result<GetBeaconBlockResponse, RequestError>| {
                    let input = match result {
                        Ok(resp) => PoolScopedInput::BeaconBlockSyncResponseReceived {
                            epoch,
                            block: resp.block,
                        },
                        Err(err) => PoolScopedInput::BeaconBlockSyncFetchFailed {
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

    fn beacon_tip(&self) -> Option<Epoch> {
        self.process.beacon_storage.latest_committed_epoch()
    }

    fn now(&self) -> LocalTimestamp {
        self.now
    }
}
