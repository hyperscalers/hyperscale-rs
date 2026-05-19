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

use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{Engine, TransactionValidation};
use hyperscale_storage::Storage;

use crate::event::ShardEvent;
use crate::io_loop::{DispatchHandles, SharedTopologySnapshot};

/// Process-scoped resources shared across every hosted shard.
///
/// Construction order: build the event-channel pair first; pass the
/// `Sender` here, keep the `Receiver` for the runner / harness. Wrap the
/// constructed `ProcessIo` in `Arc` for sharing.
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
    /// `dispatch.spawn` site routes results back via `event_sender`.
    pub(crate) dispatch: D,

    /// Channel back to the pinned-thread event loop.
    ///
    /// Off-thread work spawned via `dispatch.spawn(pool, ...)` returns
    /// results here as [`ShardEvent`] envelopes (a `NodeInput` plus its
    /// hosted-shard tag), which the next pinned-thread `step()`
    /// iteration drains.
    ///
    /// Phase 3 will replace this with a per-shard
    /// `HashMap<ShardGroupId, Sender<ShardEvent>>` so each shard's
    /// pinned thread receives only its own events.
    pub(crate) event_sender: Sender<ShardEvent>,

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
        event_sender: Sender<ShardEvent>,
        topology_snapshot: SharedTopologySnapshot,
        dispatch_handles: Arc<DispatchHandles<S, N, E>>,
        tx_validator: Arc<TransactionValidation>,
    ) -> Self {
        Self {
            network,
            dispatch,
            event_sender,
            topology_snapshot,
            dispatch_handles,
            tx_validator,
        }
    }
}
