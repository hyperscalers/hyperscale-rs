//! Process-scoped I/O state shared across every hosted shard.
//!
//! `ProcessIo` holds the resources that are logically one per node (network
//! adapter, dispatch pool, tx validator, topology snapshot, dispatch
//! handles). It owns no event loop and has no per-step scratch — that's
//! [`ShardLoop`]'s job. Wrapped in `Arc` so off-thread closures and
//! per-shard drivers can share the same handle.
//!
//! [`ShardLoop`]: crate::shard_loop::ShardLoop

mod canonical_txs;
mod network_handlers;
mod tx_status;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
pub(crate) use canonical_txs::CanonicalTxs;
use crossbeam::channel::Sender;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::TransactionValidation;
use hyperscale_network::Network;
use hyperscale_storage::{BeaconStorage, ShardStorage};
use hyperscale_types::{
    Epoch, RoutableTransaction, RoutingCommittees, ShardId, TopologySnapshot, ValidatorId,
};
pub(crate) use network_handlers::register_shard_request_handlers;
pub use tx_status::TxStatusCache;

use crate::beacon::BeaconCommitCoordinator;
use crate::event::{HostEvent, ShardScopedInput};
use crate::shard_loop::{DispatchHandles, SharedTopologySnapshot};

/// Lock-free per-shard event-sender map.
///
/// Handler closures and RPC fan-out `.load()` for an atomic snapshot on
/// every use; the map is swapped only when shard participation changes,
/// and the reconfiguring thread is the sole writer.
pub(crate) type SharedShardSenders = Arc<ArcSwap<BTreeMap<ShardId, Sender<HostEvent>>>>;

/// Beacon-signing seat for one hosted validator: which shard's vnode
/// currently signs beacon consensus under the validator's identity,
/// and the highest SPC epoch any holder has signed for — the fence a
/// successor must clear before claiming a vacated seat.
struct BeaconSignerSeat {
    /// Shard loop whose vnode holds the seat; `None` once the holder's
    /// teardown released it.
    shard: Option<ShardId>,
    /// Highest SPC epoch a holder was allowed to sign for. Recorded at
    /// the dispatch funnel before the signature exists, so the fence is
    /// conservative even when the dispatched action never sends.
    max_signed_epoch: Epoch,
}

impl BeaconSignerSeat {
    const fn vacant() -> Self {
        Self {
            shard: None,
            max_signed_epoch: Epoch::GENESIS,
        }
    }

    /// Whether `my_shard`'s vnode may sign for `epoch` under this seat:
    /// the holder records the epoch and passes; a vacant seat is
    /// claimed when `epoch` clears the fence (the teardown handoff);
    /// anything else is denied.
    fn allow(&mut self, my_shard: ShardId, epoch: Epoch) -> bool {
        match self.shard {
            Some(shard) if shard == my_shard => {
                self.max_signed_epoch = self.max_signed_epoch.max(epoch);
                true
            }
            None if epoch > self.max_signed_epoch => {
                self.shard = Some(my_shard);
                self.max_signed_epoch = epoch;
                true
            }
            Some(_) | None => false,
        }
    }
}

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
    /// results here as [`HostEvent`] envelopes (a `NodeInput` plus its
    /// hosted-shard tag), routed to the shard's sender so the right
    /// driver picks them up on its next iteration. Inbound network
    /// handlers route by the shard tag inside the decoded payload,
    /// loading the map per message so a shard added or dropped at
    /// runtime is observed immediately.
    pub(crate) shard_event_senders: SharedShardSenders,

    /// Per-host channel back to the runner for beacon events routed to the
    /// shard-less follower pool. In the sim this is the host's single event
    /// channel (shared with the per-shard senders); the beacon-block gossip
    /// follower pushes [`HostEvent::Beacon`] here for the pool to fold.
    /// The host-level beacon handler is registered on every host but only
    /// pushes when [`Self::beacon_route_active`] is set, so the channel
    /// carries no traffic until a pool is draining it.
    pub(crate) beacon_event_sender: Sender<HostEvent>,

    /// Whether a follower pool is currently draining
    /// [`Self::beacon_event_sender`]. The host-level beacon gossip handler
    /// is registered unconditionally (so a pool built at runtime is fed),
    /// but routes a block only while this is set — toggled true when a pool
    /// is built and false when it is torn down. Without the gate, a host
    /// with no live pool would either silently swallow blocks (handler
    /// missing) or back the channel up unbounded (handler pushing into a
    /// drained-by-no-one channel).
    beacon_route_active: Arc<AtomicBool>,

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

    /// Process-wide latest-status-per-transaction view. Every shard
    /// thread writes through its monotonic merge; RPC threads read
    /// lock-free.
    pub(crate) tx_status: Arc<TxStatusCache>,

    /// Canonical `RoutableTransaction` instance per tx hash, so
    /// co-hosted shards validating the same transaction share one
    /// `OnceLock` verdict instead of each running the full
    /// signature/SBOR validation. `Arc` so the gossip handler closure
    /// can hold it without capturing the whole `ProcessIo`.
    pub(crate) canonical_txs: Arc<CanonicalTxs>,

    /// One beacon-signing seat per hosted validator. A validator's
    /// vnodes overlap across a split flip or a relocation drain, and
    /// every vnode runs the full beacon protocol under the same
    /// identity — two of them emitting independently derived SPC
    /// messages is equivocation, which the beacon fold jails
    /// permanently. `ShardLoop::dispatch_delegated_action` drops any
    /// beacon signing action [`Self::allow_beacon_signing`] denies, so
    /// exactly one vnode per validator signs while the rest track
    /// passively.
    ///
    /// The fence is in-memory and scoped to one process lifetime: a
    /// restart clears every seat and the per-seat high-water epoch, so the
    /// first post-restart emission per validator claims its seat freshly.
    /// A different vnode winning the seat within an epoch the validator
    /// already signed before the restart would equivocate — the fence
    /// guards concurrent vnodes, not restarts.
    beacon_signers: Mutex<HashMap<ValidatorId, BeaconSignerSeat>>,
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
        shard_event_senders: BTreeMap<ShardId, Sender<HostEvent>>,
        beacon_event_sender: Sender<HostEvent>,
        topology_snapshot: SharedTopologySnapshot,
        dispatch_handles: Arc<DispatchHandles<S, N>>,
        tx_validator: Arc<TransactionValidation>,
        beacon_storage: Arc<dyn BeaconStorage>,
    ) -> Self {
        Self {
            network,
            dispatch,
            shard_event_senders: Arc::new(ArcSwap::from_pointee(shard_event_senders)),
            beacon_event_sender,
            beacon_route_active: Arc::new(AtomicBool::new(false)),
            topology_snapshot,
            dispatch_handles,
            tx_validator,
            beacon_storage,
            beacon_commit: BeaconCommitCoordinator::new(),
            tx_status: Arc::new(TxStatusCache::new()),
            canonical_txs: Arc::new(CanonicalTxs::new()),
            beacon_signers: Mutex::new(HashMap::new()),
        }
    }

    /// Mark whether a follower pool is draining the beacon channel. Set
    /// true when a pool is built (host construction with followers,
    /// `add_pooled_vnode`, or the production supervisor's pool thread) and
    /// false when it is torn down. The host-level beacon gossip handler
    /// reads this before routing a committed block, so a pool built after
    /// startup is fed and a host with no live pool drops blocks rather than
    /// backing the channel up.
    pub fn set_beacon_route_active(&self, active: bool) {
        self.beacon_route_active.store(active, Ordering::Release);
    }

    /// A clone of the route-active flag for the host-level beacon handler
    /// closure to read per block, without capturing the whole `ProcessIo`.
    pub(crate) fn beacon_route_active(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.beacon_route_active)
    }

    /// Seat `validator`'s beacon signing on `shard`'s vnode. First
    /// assign wins: a vnode seated while the validator already holds a
    /// seat (live or released) is born passive. Claiming a released
    /// seat happens at the dispatch funnel under the epoch fence, so a
    /// flip or relocation overlap can never produce two signers for
    /// one epoch.
    ///
    /// # Panics
    /// Panics if the seat registry mutex is poisoned.
    pub fn assign_beacon_signer(&self, validator: ValidatorId, shard: ShardId) {
        self.beacon_signers
            .lock()
            .expect("beacon signer registry lock")
            .entry(validator)
            .or_insert(BeaconSignerSeat {
                shard: Some(shard),
                max_signed_epoch: Epoch::GENESIS,
            });
    }

    /// Release `validator`'s beacon-signing seat at `shard`'s teardown.
    /// The epoch fence stays behind: a surviving vnode claims the
    /// vacant seat on its next emission for an epoch strictly above
    /// anything the dead vnode was allowed to sign.
    ///
    /// # Panics
    /// Panics if the seat registry mutex is poisoned.
    pub fn release_beacon_signer(&self, validator: ValidatorId, shard: ShardId) {
        if let Some(seat) = self
            .beacon_signers
            .lock()
            .expect("beacon signer registry lock")
            .get_mut(&validator)
            && seat.shard == Some(shard)
        {
            seat.shard = None;
        }
    }

    /// Whether `my_shard`'s vnode may emit a beacon signing action for
    /// `epoch` under `validator`'s identity — one lock for
    /// check-and-record, per [`BeaconSignerSeat::allow`]. A validator
    /// with no seat on record claims one, so single-vnode hosts behave
    /// identically with or without driver wiring.
    ///
    /// # Panics
    /// Panics if the seat registry mutex is poisoned.
    pub fn allow_beacon_signing(
        &self,
        validator: ValidatorId,
        my_shard: ShardId,
        epoch: Epoch,
    ) -> bool {
        self.beacon_signers
            .lock()
            .expect("beacon signer registry lock")
            .entry(validator)
            .or_insert(BeaconSignerSeat::vacant())
            .allow(my_shard, epoch)
    }

    /// Process-level beacon chain storage handle.
    #[must_use]
    pub fn beacon_storage(&self) -> &Arc<dyn BeaconStorage> {
        &self.beacon_storage
    }

    /// Process-wide transaction status cache, shared with external RPC
    /// consumers.
    #[must_use]
    pub const fn tx_status(&self) -> &Arc<TxStatusCache> {
        &self.tx_status
    }

    /// Shared network handle. Runner-level drivers (e.g. the shard
    /// supervisor's snap-sync bootstrap) issue requests through it.
    #[must_use]
    pub const fn network(&self) -> &Arc<N> {
        &self.network
    }

    /// Shared lock-free topology snapshot handle, refreshed on every
    /// `Action::TopologyChanged`. Long-running consumers hold the
    /// handle and re-load to observe beacon commits.
    #[must_use]
    pub const fn topology(&self) -> &SharedTopologySnapshot {
        &self.topology_snapshot
    }

    /// Sender for `shard`'s event channel (an owned clone — crossbeam
    /// senders are cheap `Arc` handles).
    ///
    /// # Panics
    /// Panics if `shard` isn't hosted by this `ProcessIo`.
    pub(crate) fn shard_sender(&self, shard: ShardId) -> Sender<HostEvent> {
        self.shard_event_senders
            .load()
            .get(&shard)
            .unwrap_or_else(|| panic!("shard {shard:?} not hosted by this ProcessIo"))
            .clone()
    }

    /// Install the event sender for a newly hosted `shard`. The
    /// reconfiguring thread is the sole writer, so the clone-modify-store
    /// needs no CAS retry; concurrent readers keep their loaded snapshot.
    pub(crate) fn insert_shard_sender(&self, shard: ShardId, sender: Sender<HostEvent>) {
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
        } else if let Some(host) = senders.keys().copied().next() {
            // No touched shard is hosted, but the host carries some shard
            // it can flush outbound gossip through.
            SubmitFanout::GossipOnly {
                host,
                touched_shards,
            }
        } else {
            // A pooled-only beacon follower hosts no shard at all — it runs
            // no pipeline to admit or gossip through.
            SubmitFanout::NoHostedShard
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
        // Seed the canonical-instance cache so gossip echoes of this tx
        // arriving on other hosted shards' topics share its validation
        // verdict.
        let tx = &self.canonical_txs.canonicalize(tx);
        let fanout = self.compute_submit_fanout(tx);
        let mut ok = true;
        match fanout {
            SubmitFanout::Admit {
                source,
                passive,
                touched_shards,
            } => {
                let env = HostEvent::shard(
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
                    let env = HostEvent::shard(
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
                let env = HostEvent::shard(
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
            SubmitFanout::NoHostedShard => {
                tracing::warn!("Dropping locally-submitted transaction: host carries no shard");
                ok = false;
            }
        }
        ok
    }
}

impl<S, N, D> ProcessIo<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Adopt a fresh topology snapshot: publish it through the lock-free
    /// `ArcSwap` so off-thread closures pick it up on their next `.load()`, and
    /// push it to the network adapter (which keys validator pubkeys and shard
    /// committees off the snapshot, and fetch routing off the terminal-clamped
    /// committees). Shared by every driver's `Action::TopologyChanged` handling
    /// — idempotent across them, the final stored value is identical.
    pub(crate) fn apply_topology(
        &self,
        topology: &Arc<TopologySnapshot>,
        routing_committees: Arc<RoutingCommittees>,
    ) {
        self.topology_snapshot.store(Arc::clone(topology));
        self.network.update_topology(Arc::clone(topology));
        self.network.update_routing_committees(routing_committees);
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
    /// The host carries no shard at all — a pooled-only beacon follower.
    /// It runs no shard pipeline to admit or gossip through, so a
    /// locally-submitted tx is dropped.
    NoHostedShard,
}
