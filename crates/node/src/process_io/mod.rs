//! Process-scoped I/O state shared across every hosted shard.
//!
//! `ProcessIo` holds the resources that are logically one per node (network
//! adapter, dispatch pool, tx validator, topology snapshot, dispatch
//! handles). It owns no event loop and has no per-step scratch — that's
//! [`ShardLoop`]'s job. Wrapped in `Arc` so off-thread closures and
//! per-shard drivers can share the same handle.
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

use crate::event::{ShardEvent, ShardScopedInput};
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
    /// transaction.
    ///
    /// If any hosted shard is in the tx's touched set, the first such
    /// shard becomes the [`SubmitFanout::Admit`] source — it admits,
    /// takes `locally_submitted` ownership, and enqueues outbound
    /// gossip for every destination (hosted or not). Remaining hosted
    /// touched shards admit only (passive co-hosts).
    ///
    /// If no hosted shard is touched, returns
    /// [`SubmitFanout::GossipOnly`] — gossip still goes out via some
    /// hosted shard, but no shard admits or takes ownership.
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

        if let Some(source) = hosted_touched.next() {
            SubmitFanout::Admit {
                source,
                passive: hosted_touched.collect(),
                touched_shards,
            }
        } else {
            // `NodeHost::new` asserts at least one hosted shard, so
            // there is always a host available to flush gossip.
            let host = self
                .shard_event_senders
                .keys()
                .copied()
                .next()
                .expect("ProcessIo hosts at least one shard");
            SubmitFanout::GossipOnly {
                host,
                touched_shards,
            }
        }
    }

    /// Fan a locally-submitted transaction out via
    /// [`Self::shard_event_senders`] according to
    /// [`Self::compute_submit_fanout`].
    ///
    /// Returns `true` if every send succeeded; `false` only on shutdown
    /// (a closed channel). Used by the production RPC submission
    /// closure — callers on tokio worker threads can invoke this
    /// concurrently because `compute_submit_fanout` only reads the
    /// lock-free topology snapshot and the immutable sender map.
    pub fn submit_transaction(&self, tx: &Arc<RoutableTransaction>) -> bool {
        let fanout = self.compute_submit_fanout(tx);
        let mut ok = true;
        match fanout {
            SubmitFanout::Admit {
                source,
                passive,
                touched_shards,
            } => {
                let env = ShardEvent::shard(
                    source,
                    ShardScopedInput::AdmitAndGossipTransaction {
                        tx: Arc::clone(tx),
                        touched_shards,
                    },
                );
                if self.shard_sender(source).send(env).is_err() {
                    ok = false;
                }
                for shard in passive {
                    let env = ShardEvent::shard(
                        shard,
                        ShardScopedInput::AdmitTransaction { tx: Arc::clone(tx) },
                    );
                    if self.shard_sender(shard).send(env).is_err() {
                        ok = false;
                    }
                }
            }
            SubmitFanout::GossipOnly {
                host,
                touched_shards,
            } => {
                let env = ShardEvent::shard(
                    host,
                    ShardScopedInput::GossipTransaction {
                        tx: Arc::clone(tx),
                        touched_shards,
                    },
                );
                if self.shard_sender(host).send(env).is_err() {
                    ok = false;
                }
            }
        }
        ok
    }
}

/// Routing decision for a locally-submitted transaction. Returned by
/// [`ProcessIo::compute_submit_fanout`]; consumed by `NodeHost` (sim)
/// or the production routing thread.
pub enum SubmitFanout {
    /// At least one hosted shard is in the tx's touched set. `source`
    /// admits, takes `locally_submitted` ownership, and gossips out;
    /// `passive` admit only.
    Admit {
        /// First hosted touched shard — source of outbound gossip and
        /// sole owner of the `locally_submitted` flag for this tx.
        source: ShardGroupId,
        /// Hosted touched shards other than the source — admit-only.
        passive: Vec<ShardGroupId>,
        /// Every shard the tx touches (declared reads ∪ writes).
        /// Carried to the source so it can enqueue outbound gossip
        /// for each destination.
        touched_shards: Vec<ShardGroupId>,
    },
    /// No hosted shard is touched by this tx. Pick any hosted shard to
    /// flush outbound gossip; no admission, no `locally_submitted`
    /// entry.
    GossipOnly {
        /// Arbitrary hosted shard chosen to enqueue outbound gossip.
        host: ShardGroupId,
        /// Every shard the tx touches (declared reads ∪ writes).
        touched_shards: Vec<ShardGroupId>,
    },
}
