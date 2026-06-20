//! Per-host driver for shard-less vnodes: the beacon-follower pool.
//!
//! A [`PoolLoop`] drives the vnodes a host runs with `shard: None` — logical
//! nodes that follow the beacon chain (adopt committed beacon blocks, track
//! topology, surface their own seat triggers) but run no shard consensus. It is
//! the lightweight sibling of [`ShardLoop`](crate::shard_loop::ShardLoop): a
//! `Vec<Vnode>` plus a cloned `Arc<ProcessIo>` and per-step scratch — no
//! `ShardIo`, no batch accumulators, no fetch host.
//!
//! A follower's entire action set is handled **inline**. The delegated-dispatch
//! path a `ShardLoop` uses is unbuildable here anyway (its `ActionContext` needs
//! a `PendingChain` a shard-less host has no storage for), and a follower's
//! actions are cheap: a beacon block's cert verifies with one BLS aggregate
//! check, and adoption only touches process-shared state (the beacon commit
//! dedup, the topology `ArcSwap`). Because a pooled vnode no-ops
//! `BeaconBlockPersisted` (it has no shard coordinators to replay into), the
//! whole `received → verify → adopt → commit` cascade runs to quiescence within
//! one [`Self::dispatch_event`], with no event-channel round trip.

use std::collections::VecDeque;
use std::sync::Arc;

use hyperscale_core::{Action, ParticipationChange, ProtocolEvent, StateMachine};
use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{CertifiedBeaconBlockVerifyContext, LocalTimestamp};
use tracing::warn;

use crate::process_io::ProcessIo;
use crate::vnode::Vnode;

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
    pub(crate) pending_reconfigurations: Vec<ParticipationChange>,

    /// Per-step scratch: count of actions the pooled vnodes produced.
    pub(crate) actions_generated: usize,
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
    pub const fn new(process: Arc<ProcessIo<S, N, D>>, vnodes: Vec<Vnode>) -> Self {
        Self {
            process,
            vnodes,
            now: LocalTimestamp::ZERO,
            pending_reconfigurations: Vec::new(),
            actions_generated: 0,
        }
    }

    /// Set the cached wall-clock time observed by `state.handle(now, _)`.
    pub const fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
    }

    /// Number of pooled vnodes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.vnodes.len()
    }

    /// Whether the pool holds no vnodes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.vnodes.is_empty()
    }

    /// Clear per-step scratch. Called by [`NodeHost::step`](crate::host::NodeHost::step)
    /// before dispatch so the drained output reflects only this step.
    pub(crate) fn clear_scratch(&mut self) {
        self.pending_reconfigurations.clear();
        self.actions_generated = 0;
    }

    /// Drive one beacon event through every pooled vnode and return the
    /// placement deltas they surfaced (the seat triggers the supervisor acts
    /// on). Clears per-step scratch first, mirroring
    /// [`ShardLoop::run_step`](crate::shard_loop::ShardLoop::run_step); used by
    /// the production pool thread, which owns the `PoolLoop` directly rather
    /// than driving it through [`NodeHost::step`](crate::host::NodeHost::step).
    pub fn run_step(&mut self, event: ProtocolEvent) -> Vec<ParticipationChange> {
        self.clear_scratch();
        self.dispatch_event(event);
        std::mem::take(&mut self.pending_reconfigurations)
    }

    /// Fan a beacon [`ProtocolEvent`] across every pooled vnode, driving each
    /// one's follower cascade to quiescence.
    pub(crate) fn dispatch_event(&mut self, event: ProtocolEvent) {
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

    /// Handle one action from a beacon follower. The set is small: verify a
    /// gossiped block, commit an adopted one, adopt a fresh topology, surface a
    /// seat trigger. Anything else either belongs to shard consensus (which a
    /// follower never runs) or to beacon-committee duty (which a pooled,
    /// never-`beacon_eligible` validator never takes on).
    fn process_action(
        &mut self,
        vnode_idx: usize,
        action: Action,
        queue: &mut VecDeque<ProtocolEvent>,
    ) {
        match action {
            Action::VerifyBeaconBlock {
                block,
                signers,
                equivocation_signers,
            } => {
                // Inline BLS verify of the SPC cert against the committee — no
                // off-thread dispatch. The result re-enters the same vnode as a
                // continuation so adoption runs within this cascade.
                let network = self.vnodes[vnode_idx]
                    .state
                    .beacon_coordinator()
                    .network_definition();
                let result = Arc::unwrap_or_clone(block)
                    .upgrade(&CertifiedBeaconBlockVerifyContext {
                        network,
                        signers: &signers,
                        equivocation_signers: &equivocation_signers,
                    })
                    .map(Arc::new)
                    .map_err(|(_, e)| e);
                queue.push_back(ProtocolEvent::BeaconBlockVerified { result });
            }
            Action::CommitBeaconBlock { block, state } => {
                // Process-scoped dedup: the first vnode to reach this
                // `(epoch, hash)` writes to the host's beacon storage. A pooled
                // vnode no-ops `BeaconBlockPersisted`, so it isn't fed back.
                self.process
                    .beacon_commit
                    .commit(&self.process.beacon_storage, &block, &state);
            }
            Action::TopologyChanged {
                topology_snapshot,
                routing_committees,
            } => {
                self.process
                    .apply_topology(&topology_snapshot, routing_committees);
            }
            Action::ReconfigureParticipation(change) => {
                self.pending_reconfigurations.push(change);
            }
            // A follower is never on the beacon committee, so its consensus
            // timers fire only into handlers that no-op; drop them rather than
            // schedule dead timers. A follower likewise never amplifies blocks.
            Action::SetTimer { .. }
            | Action::CancelTimer { .. }
            | Action::BroadcastBeaconBlock { .. } => {}
            // Catch-up sync is a backstop for dropped gossip; deferred until a
            // pooled host's standalone beacon-sync driver lands.
            Action::StartBeaconBlockSync { .. } => {
                warn!("PoolLoop: StartBeaconBlockSync not yet driven (gossip-only follower)");
            }
            other => {
                warn!(
                    action = other.type_name(),
                    "PoolLoop: unexpected action from a beacon follower — dropping"
                );
            }
        }
    }
}
