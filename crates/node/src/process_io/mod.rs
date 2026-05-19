//! Process-scoped I/O state shared across every hosted shard.
//!
//! `ProcessIo` holds the resources that are logically one per node (network
//! adapter, dispatch pool, tx validator, topology snapshot, dispatch
//! handles). It owns no event loop and has no per-step scratch — that's
//! [`ShardLoop`]'s job (phase 2). Wrapped in `Arc` so off-thread closures
//! and per-shard drivers can share the same handle.
//!
//! [`ShardLoop`]: crate::shard_loop::ShardLoop

mod network_handlers;

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{Engine, TransactionValidation};
use hyperscale_storage::Storage;
use hyperscale_types::{RoutableTransaction, ShardGroupId, shard_for_node};

use crate::event::ShardEvent;
use crate::shard_loop::{DispatchHandles, SharedTopologySnapshot};

/// Process-scoped resources shared across every hosted shard.
///
/// Construction order: build one event-channel pair per hosted shard
/// first; pass the resulting sender map here, keep the receivers for
/// the runner / harness. Wrap the constructed `ProcessIo` in `Arc` for
/// sharing.
pub struct ProcessIo<S, N, D, E>
where
    S: Storage,
    D: Dispatch,
    E: Engine,
{
    /// Network sender plus the registry of inbound gossip / request
    /// handlers installed at `init` time. `Arc` so handler closures
    /// and dispatch jobs can broadcast / reply without re-entering
    /// the pinned thread.
    pub(crate) network: Arc<N>,

    /// Thread-pool scheduler for off-thread work (crypto verify,
    /// tx validation, block-commit persistence, fetch-serve). Each
    /// `dispatch.spawn` site routes results back via the emitting
    /// shard's entry in [`Self::shard_event_senders`].
    pub(crate) dispatch: D,

    /// Per-shard channels back to each shard's driver.
    ///
    /// Off-thread work spawned via `dispatch.spawn(pool, ...)` returns
    /// results here as [`ShardEvent`] envelopes (a `NodeInput` plus its
    /// hosted-shard tag), routed to the shard's sender so the right
    /// driver picks them up on its next iteration. Inbound network
    /// handlers route by the shard tag inside the decoded payload.
    pub(crate) shard_event_senders: HashMap<ShardGroupId, Sender<ShardEvent>>,

    /// Lock-free topology snapshot shared with network handler closures
    /// and delegated dispatch jobs. The pinned thread is the sole writer
    /// (via `Action::TopologyChanged`); all other readers `.load()` for
    /// an atomic snapshot.
    pub(crate) topology_snapshot: SharedTopologySnapshot,

    /// See [`DispatchHandles`]. Cloned once per delegated-action dispatch.
    pub(crate) dispatch_handles: Arc<DispatchHandles<S, N, E>>,

    /// Stateless transaction validator (signature + format + EC checks).
    /// `Arc` so it can be cloned into the `tx_validation` pool closure
    /// on each batch flush.
    pub(crate) tx_validator: Arc<TransactionValidation>,
}

impl<S, N, D, E> ProcessIo<S, N, D, E>
where
    S: Storage,
    D: Dispatch,
    E: Engine,
{
    /// Construct a `ProcessIo` from its shared resources. Callers wrap
    /// the result in `Arc` and share with every `ShardLoop` plus
    /// off-thread closure capture sites.
    pub(crate) const fn new(
        network: Arc<N>,
        dispatch: D,
        shard_event_senders: HashMap<ShardGroupId, Sender<ShardEvent>>,
        topology_snapshot: SharedTopologySnapshot,
        dispatch_handles: Arc<DispatchHandles<S, N, E>>,
        tx_validator: Arc<TransactionValidation>,
    ) -> Self {
        Self {
            network,
            dispatch,
            shard_event_senders,
            topology_snapshot,
            dispatch_handles,
            tx_validator,
        }
    }

    /// Sender for `shard`'s event channel.
    ///
    /// # Panics
    /// Panics if `shard` isn't hosted by this `ProcessIo`.
    pub(crate) fn shard_sender(&self, shard: ShardGroupId) -> &Sender<ShardEvent> {
        self.shard_event_senders
            .get(&shard)
            .unwrap_or_else(|| panic!("shard {shard:?} not hosted by this ProcessIo"))
    }

    /// Compute the cross-shard admission plan for a locally-submitted
    /// transaction. The first hosted touched shard becomes the gossip
    /// source — it receives the full `touched_shards` list so it can
    /// enqueue outbound gossip for each destination (hosted or not).
    /// Other hosted touched shards only admit.
    ///
    /// If no hosted shard is touched, the gossip still goes out via
    /// some hosted shard (any shard's `outbound_gossip_batches` works —
    /// the wire shape carries no source identity).
    pub(crate) fn compute_submit_fanout(&self, tx: &RoutableTransaction) -> SubmitFanout {
        let num_shards = self.topology_snapshot.load().num_shards();
        let touched_shards: Vec<ShardGroupId> = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .map(|node_id| shard_for_node(node_id, num_shards))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let mut hosted_touched = self
            .shard_event_senders
            .keys()
            .copied()
            .filter(|s| touched_shards.contains(s));
        let source_shard = hosted_touched
            .next()
            .or_else(|| self.shard_event_senders.keys().copied().next());
        let other_hosted: Vec<ShardGroupId> = hosted_touched.collect();

        SubmitFanout {
            touched_shards,
            source_shard,
            other_hosted,
        }
    }
}

/// Routing decision for a locally-submitted transaction. Returned by
/// [`ProcessIo::compute_submit_fanout`]; consumed by `NodeHost` (sim)
/// or the production routing thread.
pub struct SubmitFanout {
    /// Every shard the tx touches (declared reads ∪ writes). Used as
    /// the `touched_shards` payload of
    /// [`ShardScopedInput::AdmitAndGossipTransaction`] so the source
    /// shard knows where to send outbound gossip.
    ///
    /// [`ShardScopedInput::AdmitAndGossipTransaction`]: crate::event::ShardScopedInput::AdmitAndGossipTransaction
    pub touched_shards: Vec<ShardGroupId>,
    /// Hosted shard chosen as the gossip source, or `None` if the
    /// node hosts no shards at all (impossible by construction —
    /// `NodeHost::new` asserts at least one hosted shard).
    pub source_shard: Option<ShardGroupId>,
    /// Hosted touched shards other than the source — admit-only.
    pub other_hosted: Vec<ShardGroupId>,
}
