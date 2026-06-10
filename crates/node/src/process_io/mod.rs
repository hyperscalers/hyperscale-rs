//! Process-scoped I/O state shared across every hosted shard.
//!
//! `ProcessIo` holds the resources that are logically one per node (network
//! adapter, dispatch pool, tx validator, topology snapshot, dispatch
//! handles). It owns no event loop and has no per-step scratch — that's
//! [`ShardLoop`]'s job. Wrapped in `Arc` so off-thread closures and
//! per-shard drivers can share the same handle.
//!
//! [`ShardLoop`]: crate::shard_loop::ShardLoop

mod beacon_commit;
mod network_handlers;

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use arc_swap::ArcSwap;
pub(crate) use beacon_commit::BeaconCommitCoordinator;
use crossbeam::channel::Sender;
use hyperscale_beacon::proposal_pool::BeaconProposalPool;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::TransactionValidation;
use hyperscale_storage::{BeaconStorage, ShardStorage};
use hyperscale_types::{RoutableTransaction, ShardId};
pub(crate) use network_handlers::register_shard_request_handlers;

use crate::event::{ShardEvent, ShardScopedInput};
use crate::shard_loop::{DispatchHandles, SharedTopologySnapshot};

/// Lock-free per-shard event-sender map.
///
/// Handler closures and RPC fan-out `.load()` for an atomic snapshot on
/// every use; the map is swapped only when shard participation changes,
/// and the reconfiguring thread is the sole writer.
pub(crate) type SharedShardSenders = Arc<ArcSwap<HashMap<ShardId, Sender<ShardEvent>>>>;

/// Process-scoped resources shared across every hosted shard.
///
/// Construction order: build one event-channel pair per hosted shard
/// first; pass the resulting sender map here, keep the receivers for
/// the runner / harness. Wrap the constructed `ProcessIo` in `Arc` for
/// sharing.
pub struct ProcessIo<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
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
    /// handlers route by the shard tag inside the decoded payload,
    /// loading the map per message so a shard added or dropped at
    /// runtime is observed immediately.
    pub(crate) shard_event_senders: SharedShardSenders,

    /// Lock-free topology snapshot shared with network handler closures
    /// and delegated dispatch jobs. The pinned thread is the sole writer
    /// (via `Action::TopologyChanged`); all other readers `.load()` for
    /// an atomic snapshot.
    pub(crate) topology_snapshot: SharedTopologySnapshot,

    /// See [`DispatchHandles`]. Cloned once per delegated-action dispatch.
    pub(crate) dispatch_handles: Arc<DispatchHandles<S, N>>,

    /// Stateless transaction validator (signature + format + EC checks).
    /// `Arc` so it can be cloned into the `tx_validation` pool closure
    /// on each batch flush.
    pub(crate) tx_validator: Arc<TransactionValidation>,

    /// Process-level beacon chain storage. One handle per host,
    /// shared across every vnode's `Action::CommitBeaconBlock`
    /// handler. The implementation serializes writes internally
    /// (`RocksDbBeaconStorage::commit_lock`); reads remain lock-free.
    pub(crate) beacon_storage: Arc<dyn BeaconStorage>,

    /// First leg of the beacon-commit dedup: lets only the first
    /// co-hosted vnode to reach a given `(epoch, hash)` write it to
    /// `beacon_storage`, so the others skip the round-trip instead of
    /// bottoming out as idempotent no-ops.
    pub(crate) beacon_commit: BeaconCommitCoordinator,

    /// Host-shared per-epoch `BeaconProposal` pool. Same `Arc` lives
    /// on every co-hosted vnode's `BeaconCoordinator` and on the
    /// inbound `GetBeaconProposalRequest` network handler closure;
    /// writes (admit / reset) come only from the shard pinned thread,
    /// reads from the network worker are wait-free.
    pub(crate) beacon_proposal_pool: Arc<BeaconProposalPool>,
}

impl<S, N, D> ProcessIo<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    /// Construct a `ProcessIo` from its shared resources. Callers wrap
    /// the result in `Arc` and share with every `ShardLoop` plus
    /// off-thread closure capture sites.
    #[allow(clippy::too_many_arguments)] // every field threads through one constructor
    pub(crate) fn new(
        network: Arc<N>,
        dispatch: D,
        shard_event_senders: HashMap<ShardId, Sender<ShardEvent>>,
        topology_snapshot: SharedTopologySnapshot,
        dispatch_handles: Arc<DispatchHandles<S, N>>,
        tx_validator: Arc<TransactionValidation>,
        beacon_storage: Arc<dyn BeaconStorage>,
        beacon_proposal_pool: Arc<BeaconProposalPool>,
    ) -> Self {
        Self {
            network,
            dispatch,
            shard_event_senders: Arc::new(ArcSwap::from_pointee(shard_event_senders)),
            topology_snapshot,
            dispatch_handles,
            tx_validator,
            beacon_storage,
            beacon_commit: BeaconCommitCoordinator::new(),
            beacon_proposal_pool,
        }
    }

    /// Process-level beacon chain storage handle.
    #[must_use]
    pub fn beacon_storage(&self) -> &Arc<dyn BeaconStorage> {
        &self.beacon_storage
    }

    /// Host-shared per-epoch beacon proposal pool.
    #[must_use]
    pub const fn beacon_proposal_pool(&self) -> &Arc<BeaconProposalPool> {
        &self.beacon_proposal_pool
    }

    /// Sender for `shard`'s event channel (an owned clone — crossbeam
    /// senders are cheap `Arc` handles).
    ///
    /// # Panics
    /// Panics if `shard` isn't hosted by this `ProcessIo`.
    pub(crate) fn shard_sender(&self, shard: ShardId) -> Sender<ShardEvent> {
        self.shard_event_senders
            .load()
            .get(&shard)
            .unwrap_or_else(|| panic!("shard {shard:?} not hosted by this ProcessIo"))
            .clone()
    }

    /// Install the event sender for a newly hosted `shard`. The
    /// reconfiguring thread is the sole writer, so the clone-modify-store
    /// needs no CAS retry; concurrent readers keep their loaded snapshot.
    pub(crate) fn insert_shard_sender(&self, shard: ShardId, sender: Sender<ShardEvent>) {
        let mut map = (**self.shard_event_senders.load()).clone();
        map.insert(shard, sender);
        self.shard_event_senders.store(Arc::new(map));
    }

    /// Drop the event sender for a no-longer-hosted `shard`. Inbound
    /// handlers observing the new map reject the shard's traffic;
    /// in-flight sends on the old snapshot land in a channel that dies
    /// with its receiver.
    pub(crate) fn remove_shard_sender(&self, shard: ShardId) {
        let mut map = (**self.shard_event_senders.load()).clone();
        map.remove(&shard);
        self.shard_event_senders.store(Arc::new(map));
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
        let topology = self.topology_snapshot.load();
        let touched_shards: Vec<ShardId> = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .map(|node_id| topology.shard_for_node_id(node_id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let senders = self.shard_event_senders.load();
        let mut hosted_touched = senders
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
            let host = senders
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
        source: ShardId,
        /// Hosted touched shards other than the source — admit-only.
        passive: Vec<ShardId>,
        /// Every shard the tx touches (declared reads ∪ writes).
        /// Carried to the source so it can enqueue outbound gossip
        /// for each destination.
        touched_shards: Vec<ShardId>,
    },
    /// No hosted shard is touched by this tx. Pick any hosted shard to
    /// flush outbound gossip; no admission, no `locally_submitted`
    /// entry.
    GossipOnly {
        /// Arbitrary hosted shard chosen to enqueue outbound gossip.
        host: ShardId,
        /// Every shard the tx touches (declared reads ∪ writes).
        touched_shards: Vec<ShardId>,
    },
}
