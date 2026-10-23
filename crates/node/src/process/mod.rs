//! Process-scoped I/O state shared across every hosted shard.
//!
//! `ProcessIo` holds the resources that are logically one per node (network
//! adapter, dispatch pool, tx validator, topology snapshot, dispatch
//! handles). It owns no event loop and has no per-step scratch — that's
//! [`ShardLoop`]'s job. Wrapped in `Arc` so off-thread closures and
//! per-shard drivers can share the same handle.
//!
//! [`ShardLoop`]: crate::shard::ShardLoop

mod canonical_txs;
mod fan_out;
mod network_handlers;
mod tx_status;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
pub(crate) use canonical_txs::CanonicalTxs;
use crossbeam::channel::Sender;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{
    CodeAvailability, FetchedCells, Holds, PreviewGrants, PreviewInputs, PreviewReport,
    TickEnvironment,
};
use hyperscale_network::Network;
use hyperscale_storage::{BeaconStorage, ShardStorage, SubstateStore};
use hyperscale_types::network::request::GetCellsRequest;
use hyperscale_types::{
    Derivation, Epoch, MAX_TXS_PER_BLOCK, ShardId, TopologySchedule, TopologySnapshot, Transaction,
    Unresolved, ValidatorId, Verifier,
};
pub(crate) use network_handlers::register_shard_request_handlers;
pub use tx_status::TxStatusCache;

use crate::beacon::BeaconCommitCoordinator;
use crate::event::{Attachment, HostEvent, ShardScopedInput};
use crate::shard::cross_shard::serve_cells_request;
use crate::shard::mempool::{DeferredOrigin, DeferredTransaction};
use crate::shard::{DispatchHandles, SharedTopologySnapshot};

/// Lock-free per-shard event-sender map.
///
/// Handler closures and RPC fan-out `.load()` for an atomic snapshot on
/// every use; the map is swapped only when shard participation changes,
/// and the reconfiguring thread is the sole writer.
pub(crate) type SharedShardSenders = Arc<ArcSwap<BTreeMap<ShardId, Sender<HostEvent>>>>;

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

    /// Scheme verifier for inbound signature checks run on the process's
    /// handlers and thread pools.
    pub(crate) verifier: Arc<dyn Verifier>,

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

    /// Per-host channel back to the runner for the beacon loop's events.
    /// In the sim this is the host's single event channel (shared with the
    /// per-shard senders). Beacon gossip, what the replicas report, and the
    /// loop's own continuations and fetch answers arrive here.
    pub(crate) beacon_event_sender: Sender<HostEvent>,

    /// The serial the next beacon-loop attachment takes. Process-wide, so
    /// an attachment made by a rebuilt loop never repeats one an earlier
    /// loop on the same beacon channel made.
    next_attachment: AtomicU64,

    /// Lock-free topology snapshot shared with network handler closures
    /// and delegated dispatch jobs: the head of [`Self::topology_schedule`],
    /// published with it. Readers `.load()` for an atomic snapshot.
    pub(crate) topology_snapshot: SharedTopologySnapshot,

    /// Highest beacon epoch whose `Action::TopologyChanged` has been applied to
    /// [`Self::topology_snapshot`]. Co-hosted shard threads fold the beacon
    /// independently and publish concurrently, so a slower thread on an older
    /// epoch could otherwise overwrite a newer snapshot a sibling already
    /// stored — regressing the trie / `advanced` set the reshape handoff reads.
    /// `apply_topology` holds this lock across the epoch check and the publish,
    /// so the highest epoch's snapshot wins and the stores never reorder.
    apply_topology_epoch: Mutex<Epoch>,
    /// The beacon's window schedule as last folded by a hosted vnode:
    /// the head [`Self::topology_snapshot`] publishes, the routing
    /// committees the network keys fetches on, and the retained windows
    /// a reshape follow classifies a followed parent block under — the
    /// parent's own window, which the head no longer describes once its
    /// cut has landed, and which the parent's committee can anchor into
    /// before this host folds the commit that opens it.
    topology_schedule: ArcSwap<TopologySchedule>,

    /// See [`DispatchHandles`]. Cloned once per delegated-action dispatch.
    pub(crate) dispatch_handles: Arc<DispatchHandles<S, N>>,

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

    /// Canonical `Transaction` instance per tx hash, so
    /// co-hosted shards validating the same transaction share one
    /// `OnceLock` verdict instead of each running the full
    /// signature/decode validation. `Arc` so the gossip handler closure
    /// can hold it without capturing the whole `ProcessIo`.
    pub(crate) canonical_txs: Arc<CanonicalTxs>,

    /// Submissions held while this host seats the reshape successor they
    /// route to, oldest first. Routing reads the shard map under this
    /// lock, and every change to that map or to the topology re-routes
    /// what is held after the change, so a submission is never parked
    /// behind a change that has already released the queue.
    parked_submissions: Mutex<VecDeque<Arc<Transaction>>>,
}

/// How many submissions a host holds while it seats a reshape successor:
/// one block's worth, since the successor's first block carries no more.
/// The oldest goes when a new one arrives.
const MAX_PARKED_SUBMISSIONS: usize = MAX_TXS_PER_BLOCK;

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
        verifier: Arc<dyn Verifier>,
        dispatch: D,
        shard_event_senders: BTreeMap<ShardId, Sender<HostEvent>>,
        beacon_event_sender: Sender<HostEvent>,
        topology_snapshot: SharedTopologySnapshot,
        topology_schedule: Arc<TopologySchedule>,
        dispatch_handles: Arc<DispatchHandles<S, N>>,
        beacon_storage: Arc<dyn BeaconStorage>,
    ) -> Self
    where
        N: Network,
    {
        // Routing is otherwise empty until the beacon's first commit
        // folds a topology, which is up to an epoch after a restart.
        // Inside that window every fetch to a shard outside the head —
        // a successor's queries at its predecessor, a probe of a
        // departed counterpart — resolves no committee and fails at the
        // transport before it reaches a peer.
        network.update_routing_committees(Arc::new(topology_schedule.routing_committees()));
        Self {
            network,
            verifier,
            dispatch,
            shard_event_senders: Arc::new(ArcSwap::from_pointee(shard_event_senders)),
            beacon_event_sender,
            next_attachment: AtomicU64::new(0),
            topology_snapshot,
            apply_topology_epoch: Mutex::new(Epoch::GENESIS),
            topology_schedule: ArcSwap::new(topology_schedule),
            dispatch_handles,
            beacon_storage,
            beacon_commit: BeaconCommitCoordinator::new(),
            tx_status: Arc::new(TxStatusCache::new()),
            canonical_txs: Arc::new(CanonicalTxs::new()),
            parked_submissions: Mutex::new(VecDeque::new()),
        }
    }

    /// The host's beacon loop's channel.
    #[must_use]
    pub const fn beacon_event_sender(&self) -> &Sender<HostEvent> {
        &self.beacon_event_sender
    }

    /// A fresh attachment of `validator` to the beacon loop.
    pub(crate) fn attach(&self, validator: ValidatorId) -> Attachment {
        Attachment::new(
            validator,
            self.next_attachment.fetch_add(1, Ordering::Relaxed),
        )
    }

    /// Process-level beacon chain storage handle.
    #[must_use]
    pub fn beacon_storage(&self) -> &Arc<dyn BeaconStorage> {
        &self.beacon_storage
    }

    /// This node's derivation, held by its engine — what a vnode seated
    /// at runtime resolves envelopes against.
    #[must_use]
    pub fn derivation(&self) -> Arc<dyn Derivation> {
        self.dispatch_handles.executor.derivation()
    }

    /// This node's code availability, held by the same engine — what a
    /// vnode seated at runtime holds its tick dispatch to.
    #[must_use]
    pub fn code(&self) -> Arc<dyn CodeAvailability> {
        Arc::clone(&self.dispatch_handles.executor) as Arc<dyn CodeAvailability>
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

    /// The beacon's window schedule as last folded on this host.
    #[must_use]
    pub fn topology_schedule(&self) -> Arc<TopologySchedule> {
        self.topology_schedule.load_full()
    }

    /// Shared lock-free topology snapshot handle, refreshed on every
    /// `Action::TopologyChanged`. Long-running consumers hold the
    /// handle and re-load to observe beacon commits.
    #[must_use]
    pub const fn topology_snapshot(&self) -> &SharedTopologySnapshot {
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
    /// If no hosted shard is touched but this host is still seating the
    /// reshape successor a touched shard is, the submission is parked
    /// ([`SubmitFanout::Parked`]) and routed again once the host's shards
    /// or the topology change. No peer runs that successor yet either, so
    /// gossip to it would reach nobody.
    ///
    /// Otherwise, if no hosted shard is touched, returns
    /// [`SubmitFanout::GossipOnly`] — gossip still goes out via some
    /// hosted shard, but no shard admits or takes ownership.
    pub(crate) fn compute_submit_fanout(&self, tx: &Arc<Transaction>) -> SubmitFanout {
        // Ingress bytes are unverified, and routing is a derivation the
        // envelope has to earn: asking an envelope that derives no
        // routing which shards it touches is asking for an answer it
        // does not have.
        if let Err(error) = tx.try_derived(self.dispatch_handles.executor.derivation().as_ref()) {
            // A gap and a refusal read identically from the submitter's
            // side and are not the same thing. A gap names records this
            // node has not seen, and the same envelope derives wherever
            // they landed, so it waits on a hosted shard while the fetch
            // runs instead of being dropped at the door.
            let wanted = error.unresolved().cloned().unwrap_or_default();
            if !wanted.is_empty()
                && let Some(host) = self.shard_event_senders.load().keys().copied().next()
            {
                return SubmitFanout::WantsRecords { host, wanted };
            }
            tracing::warn!(
                reason = %error,
                "Dropping locally-submitted transaction: it derives no routing"
            );
            return SubmitFanout::Underivable;
        }
        let Some((hosted, touched_shards)) = self.route_or_park(tx) else {
            return SubmitFanout::Parked;
        };
        let mut hosted_touched = hosted
            .iter()
            .copied()
            .filter(|s| touched_shards.contains(s));

        if let Some(source) = hosted_touched.next() {
            SubmitFanout::Admit {
                source,
                passive: hosted_touched.collect(),
                touched_shards,
            }
        } else if let Some(host) = hosted.first().copied() {
            // No touched shard is hosted, but the host carries some shard
            // it can flush outbound gossip through.
            SubmitFanout::GossipOnly {
                host,
                touched_shards,
            }
        } else {
            // A host seated nowhere runs no pipeline to admit or gossip
            // through.
            SubmitFanout::NoHostedShard
        }
    }

    /// The shards this host serves and the shards a derived `tx` touches,
    /// or `None` once `tx` is parked because none of the first is among
    /// the second and the host is still seating the successor one is.
    /// Both are read under the parking lock, so a change that releases the
    /// queue either finds this submission in it or is seen by this read.
    fn route_or_park(&self, tx: &Arc<Transaction>) -> Option<(Vec<ShardId>, Vec<ShardId>)> {
        let mut parked = self
            .parked_submissions
            .lock()
            .expect("parked submissions lock");
        let topology = self.topology_snapshot.load();
        let touched: Vec<ShardId> = topology.all_shards_for_transaction(tx);
        let hosted: Vec<ShardId> = self.shard_event_senders.load().keys().copied().collect();
        if hosted.iter().any(|shard| touched.contains(shard))
            || !seating_successor(&topology, &hosted, &touched)
        {
            return Some((hosted, touched));
        }
        if parked.len() >= MAX_PARKED_SUBMISSIONS
            && let Some(evicted) = parked.pop_front()
        {
            tracing::warn!(
                tx_hash = ?evicted.hash(),
                "Dropping a parked submission: the queue is full"
            );
        }
        parked.push_back(Arc::clone(tx));
        None
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
    pub fn submit_transaction(&self, tx: &Arc<Transaction>) -> bool {
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
            SubmitFanout::WantsRecords { host, wanted } => {
                let env = HostEvent::shard(
                    host,
                    ShardScopedInput::RecordsWanted {
                        wanted: vec![DeferredTransaction::new(
                            Arc::clone(tx),
                            wanted,
                            DeferredOrigin::Submission,
                        )],
                    },
                );
                if self.shard_sender(host).send(env).is_err() {
                    ok = false;
                }
            }
            SubmitFanout::Parked => {}
            SubmitFanout::Underivable => ok = false,
        }
        ok
    }

    /// Route every parked submission again against the current shards and
    /// topology. Whatever the fanout now yields is its answer, a renewed
    /// park included.
    pub(crate) fn release_parked_submissions(&self) {
        let released = std::mem::take(
            &mut *self
                .parked_submissions
                .lock()
                .expect("parked submissions lock"),
        );
        for tx in released {
            self.submit_transaction(&tx);
        }
    }
}

/// Whether this host is still seating the reshape successor of a shard it
/// serves, and `touched` reaches that successor: a hosted predecessor
/// mid-handoff whose trie line holds a touched shard and no other hosted
/// one. Once the host serves any shard on that line, the handoff it was
/// waiting on has reached it.
fn seating_successor(topology: &TopologySnapshot, hosted: &[ShardId], touched: &[ShardId]) -> bool {
    let on_line = |a: ShardId, b: ShardId| a.is_ancestor_of(b) || b.is_ancestor_of(a);
    hosted.iter().any(|&predecessor| {
        topology.reshape_handoff_pending(predecessor)
            && touched.iter().any(|&shard| on_line(predecessor, shard))
            && !hosted
                .iter()
                .any(|&other| other != predecessor && on_line(predecessor, other))
    })
}

impl<S, N, D> ProcessIo<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// What `tx` would do against a hosted shard's committed state.
    ///
    /// Answered on the calling thread and not on the shard driver's.
    /// That is the whole shape of this: a preview is a full VM run, and
    /// a maximal envelope is tens of milliseconds of it — against a
    /// block cadence where the driver has a hundred and twenty-five to
    /// execute in. Handing the driver an unauthenticated RPC's worth of
    /// execution would let anyone reachable pace block production. It
    /// needs no driver anyway: the run is a read of committed state,
    /// the pending chain is already read concurrently by every inbound
    /// request handler, and the handles a run wants are the ones the
    /// dispatch pools hold.
    ///
    /// The shard is the payer's, which is where a preview is most nearly
    /// whole: the fee vault is there, so the one cell no declaration
    /// names is the one shard the answer always has. A declaration
    /// reaching further is refused by name inside the report, never
    /// answered from an absence.
    ///
    /// `None` when this node hosts no shard that could answer, or hosts
    /// it but has committed nothing to answer from.
    #[must_use]
    pub fn preview_transaction(
        &self,
        tx: &Transaction,
        grants: PreviewGrants,
    ) -> Option<Box<PreviewReport>> {
        let topology = self.topology_snapshot.load();
        // Off the envelope rather than the derivation: a preview answers
        // for envelopes derivation may refuse.
        let payer = tx.body().terms.fee_payer;
        let payer_shard = topology.shard_trie().shard_for_prefix(payer);
        let handles = self.dispatch_handles.per_shard.load();
        let chain = &handles.get(&payer_shard)?.pending_chain;

        let view = chain.view_at_persisted_tip();
        // The tip's own QC timestamp: a candidate has no committing
        // block to take a clock from, and this node's freshest committed
        // reading is the nearest thing that exists.
        let clock = chain
            .certified_header(view.base().committed_height())
            .map(|header| header.qc().weighted_timestamp())?;
        let schedule = self.topology_schedule();
        let executor = &self.dispatch_handles.executor;

        // The payer's shard reads itself, through the snapshot below;
        // every other shard the declaration reaches is asked, including
        // ones this node happens to host — those answer out of their own
        // stores rather than over the wire, but they are still asked,
        // because one snapshot answers for one shard and a cell on a
        // co-hosted shard is not in it.
        //
        // Derived before anything is fetched, because the declaration is
        // a pure function of signed content — so the fan-out gathers
        // exactly the set the run then reads.
        let reads_itself: BTreeSet<ShardId> = BTreeSet::from([payer_shard]);
        let serve_locally = |shard: ShardId, request: &GetCellsRequest| {
            handles
                .get(&shard)
                .map(|hosted| serve_cells_request(&hosted.pending_chain, request))
        };
        let fetched = executor
            .preview_reads(tx, topology.shard_trie(), &reads_itself)
            .map_or_else(
                |_| FetchedCells::default(),
                |asks| {
                    fan_out::gather(
                        &asks,
                        &topology,
                        &*self.network,
                        &self.verifier,
                        &serve_locally,
                    )
                },
            );

        Some(Box::new(executor.preview(
            &view.snapshot(),
            tx,
            &PreviewInputs {
                prices: topology.prices(),
                clock,
                env: TickEnvironment::governing(&topology, schedule.windows()),
                // What this node holds, plus whatever answered for the
                // rest. A shard in neither is refused by name: an
                // unfetched cell is never read as an empty one.
                holds: Holds {
                    trie: topology.shard_trie().clone(),
                    shards: reads_itself,
                    fetched,
                },
                grants,
            },
        )))
    }

    /// Adopt the schedule folded at beacon `epoch`: publish its head
    /// through the lock-free `ArcSwap` so off-thread closures pick it up on
    /// their next `.load()`, and push it to the network adapter (which keys
    /// validator pubkeys and shard committees off the head, and fetch
    /// routing off the schedule's terminal-clamped committees).
    ///
    /// Every hosted shard (and the beacon loop) calls this as it folds the beacon,
    /// concurrently across pinned threads. The store is gated monotonically on
    /// `epoch`: a fold for an epoch at or below the highest already applied is
    /// dropped, so a slower thread cannot regress the shared snapshot to an
    /// older trie / `advanced` set under another thread's newer one. A genuine
    /// same-epoch re-apply is a no-op (the value is identical for an epoch).
    pub(crate) fn apply_topology(&self, epoch: Epoch, schedule: Arc<TopologySchedule>) {
        let mut applied = self
            .apply_topology_epoch
            .lock()
            .expect("apply topology epoch lock");
        if !admit_topology_epoch(&mut applied, epoch) {
            return;
        }
        // Publish under the lock so the highest epoch's stores never reorder
        // behind a slower thread that admitted an earlier epoch.
        let head = Arc::clone(schedule.head());
        let routing_committees = Arc::new(schedule.routing_committees());
        self.topology_snapshot.store(Arc::clone(&head));
        self.topology_schedule.store(schedule);
        self.network.update_topology(head);
        self.network.update_routing_committees(routing_committees);
        drop(applied);
        self.release_parked_submissions();
    }
}

/// Advance the highest-applied topology epoch to `incoming`, returning whether
/// it supersedes what was already applied. An epoch at or below `applied` is
/// dropped (a stale or duplicate fold); a newer one advances the watermark.
/// The caller holds the lock guarding `applied` across this and the publish, so
/// concurrent folds resolve to the highest epoch without the snapshot stores
/// reordering.
fn admit_topology_epoch(applied: &mut Epoch, incoming: Epoch) -> bool {
    if incoming <= *applied {
        return false;
    }
    *applied = incoming;
    true
}

/// Routing decision for a locally-submitted transaction. Returned by
/// [`ProcessIo::compute_submit_fanout`]; consumed by `NodeHost` (sim)
/// or the production routing thread.
pub(crate) enum SubmitFanout {
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
    /// No hosted shard is touched, and this host is still seating the
    /// reshape successor a touched shard is. The submission waits in
    /// [`ProcessIo`] until the host's shards or the topology change.
    Parked,
    /// The host carries no shard at all. It runs no shard pipeline to
    /// admit or gossip through, so a locally-submitted tx is dropped.
    NoHostedShard,
    /// The envelope names components this node has not seen sealed, so
    /// it derives no routing yet and there is nothing to fan out to.
    ///
    /// A gap rather than a verdict: the seals committed on the shards
    /// owning their prefixes, and the envelope derives on any node that
    /// has them. It waits on `host` while that shard fetches the records.
    WantsRecords {
        /// A hosted shard to hold the envelope and run the fetch.
        host: ShardId,
        /// What its derivation could not resolve.
        wanted: Unresolved,
    },
    /// The envelope's derivation refuses, so it names no shards to fan
    /// out to and there is nothing to gossip it on.
    ///
    /// A genuine refusal, not a gap: an envelope naming code this node
    /// has not installed reports [`Self::WantsRecords`] instead and
    /// waits for the fetch. What reaches here is inadmissible on terms
    /// every node agrees on.
    Underivable,
}

#[cfg(test)]
mod tests {
    use hyperscale_types::Epoch;

    use super::admit_topology_epoch;

    /// The topology-epoch gate admits a strictly newer fold and drops a stale
    /// or duplicate one — including an older fold arriving after a newer one,
    /// which is the co-hosting reorder the gate exists to reject.
    #[test]
    fn topology_epoch_gate_admits_newer_drops_stale() {
        let mut applied = Epoch::new(5);

        assert!(!admit_topology_epoch(&mut applied, Epoch::new(5)), "equal");
        assert!(!admit_topology_epoch(&mut applied, Epoch::new(4)), "older");
        assert_eq!(applied, Epoch::new(5), "watermark unmoved by stale folds");

        assert!(admit_topology_epoch(&mut applied, Epoch::new(6)), "newer");
        assert_eq!(applied, Epoch::new(6));

        // A slower thread's epoch-5 fold landing after the epoch-6 publish is
        // dropped rather than regressing the snapshot.
        assert!(
            !admit_topology_epoch(&mut applied, Epoch::new(5)),
            "reorder"
        );
        assert_eq!(applied, Epoch::new(6));
    }
}
