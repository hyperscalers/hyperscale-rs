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

use std::collections::HashMap;
use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{Engine, TransactionValidation};
use hyperscale_storage::Storage;
use hyperscale_types::ShardGroupId;

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
}
