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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
pub(crate) use canonical_txs::CanonicalTxs;
use crossbeam::channel::Sender;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{
    FetchedCells, Holds, PreviewGrants, PreviewInputs, PreviewReport, TickEnvironment,
};
use hyperscale_network::Network;
use hyperscale_storage::{BeaconStorage, ShardStorage, SubstateStore};
use hyperscale_types::network::request::GetCellsRequest;
use hyperscale_types::{
    Address, Derivation, Epoch, RatifyPhase, RatifyRound, ShardId, SpcView, TopologySchedule,
    Transaction, ValidatorId, Verifier,
};
pub(crate) use network_handlers::register_shard_request_handlers;
pub use tx_status::TxStatusCache;

use crate::beacon::BeaconCommitCoordinator;
use crate::event::{HostEvent, ShardScopedInput};
use crate::shard::cross_shard::serve_cells_request;
use crate::shard::mempool::{DeferredOrigin, DeferredTransaction};
use crate::shard::{DispatchHandles, SharedTopologySnapshot};

/// Lock-free per-shard event-sender map.
///
/// Handler closures and RPC fan-out `.load()` for an atomic snapshot on
/// every use; the map is swapped only when shard participation changes,
/// and the reconfiguring thread is the sole writer.
pub(crate) type SharedShardSenders = Arc<ArcSwap<BTreeMap<ShardId, Sender<HostEvent>>>>;

/// Beacon-signing fence for one hosted validator: which shard's vnode
/// signs SPC consensus within the current `(epoch, view)`, and the
/// last ratify-vote position any vnode signed.
struct BeaconSignerSeat {
    /// The `(epoch, view)` most recently signed under this validator's
    /// identity and the vnode that claimed it — the claimant's hosted
    /// shard, or `None` for the follower pool, which is a distinct
    /// claimant even when a hosted shard is `ShardId::ROOT` (a
    /// single-shard network's only leaf). A view belongs wholly to its
    /// claimant — every phase of one view comes from one coordinator's
    /// state — while any later view is claimable by whichever vnode
    /// dispatches into it first. Recorded at the dispatch funnel before
    /// the signature exists, so the fence is conservative even when the
    /// dispatched action never sends.
    claim: Option<(Epoch, SpcView, Option<ShardId>)>,
    /// Last ratify-vote position any of this validator's vnodes was
    /// allowed to sign, strictly monotone process-wide. Independent of
    /// the view claim: a torn-down vnode's successor continues from
    /// the next position rather than losing the epoch, and two live
    /// co-hosted vnodes at the same tip dedup their identical intents
    /// through the same monotonicity.
    max_ratify: Option<(Epoch, RatifyRound, RatifyPhase)>,
}

impl BeaconSignerSeat {
    const fn vacant() -> Self {
        Self {
            claim: None,
            max_ratify: None,
        }
    }

    /// Whether `my_shard`'s vnode may sign at `(epoch, view)` under
    /// this validator's identity: the claimant of the current view
    /// re-passes freely (phase progression, retries — its coordinator
    /// state machine keeps the content consistent), a strictly later
    /// view transfers the claim to the caller, and anything else is
    /// denied. Two vnodes can therefore never both sign within one
    /// `(epoch, view)` — no conflicting SPC signatures at one position
    /// — while a claimant that dies or degrades costs exactly its one
    /// view: the sibling's view-change dispatch claims the next.
    fn allow(&mut self, my_shard: Option<ShardId>, epoch: Epoch, view: SpcView) -> bool {
        match self.claim {
            Some((e, v, claimant)) if (e, v) == (epoch, view) => claimant == my_shard,
            Some((e, v, _)) if (epoch, view) > (e, v) => {
                self.claim = Some((epoch, view, my_shard));
                true
            }
            Some(_) => false,
            None => {
                self.claim = Some((epoch, view, my_shard));
                true
            }
        }
    }

    /// Whether a vnode may sign the ratify vote at `position`: strictly
    /// greater than every position already allowed, whichever vnode
    /// emitted it. Never two signatures at one `(epoch, round, phase)`
    /// — cross-vnode equivocation is impossible by construction — and
    /// never a fenced-out epoch: a successor's first fresh position
    /// passes.
    ///
    /// The ordering also drops the fast-forward re-prevote a
    /// future-round polka schedules behind its precommit (same round,
    /// lower phase). Benign: the polka is itself a prevote quorum for
    /// the value, and the lock re-prevotes at the next round.
    fn allow_ratify(&mut self, position: (Epoch, RatifyRound, RatifyPhase)) -> bool {
        if Some(position) > self.max_ratify {
            self.max_ratify = Some(position);
            true
        } else {
            false
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
            beacon_route_active: Arc::new(AtomicBool::new(false)),
            topology_snapshot,
            apply_topology_epoch: Mutex::new(Epoch::GENESIS),
            topology_schedule: ArcSwap::new(topology_schedule),
            dispatch_handles,
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

    /// Whether `my_shard`'s vnode (`None` for the follower pool) may emit
    /// a beacon signing action at `(epoch, view)` under `validator`'s
    /// identity — one lock for check-and-record, per
    /// [`BeaconSignerSeat::allow`]. A validator with no fence on record
    /// claims the view, so single-vnode hosts behave identically with or
    /// without driver wiring.
    ///
    /// # Panics
    /// Panics if the seat registry mutex is poisoned.
    pub fn allow_beacon_signing(
        &self,
        validator: ValidatorId,
        my_shard: Option<ShardId>,
        epoch: Epoch,
        view: SpcView,
    ) -> bool {
        self.beacon_signers
            .lock()
            .expect("beacon signer registry lock")
            .entry(validator)
            .or_insert(BeaconSignerSeat::vacant())
            .allow(my_shard, epoch, view)
    }

    /// Whether `validator` may sign the ratify vote at `position` —
    /// see [`BeaconSignerSeat::allow_ratify`].
    ///
    /// # Panics
    /// Panics if the seat registry mutex is poisoned.
    pub fn allow_ratify_signing(
        &self,
        validator: ValidatorId,
        position: (Epoch, RatifyRound, RatifyPhase),
    ) -> bool {
        let mut seats = self
            .beacon_signers
            .lock()
            .expect("beacon signer registry lock");
        let seat = seats.entry(validator).or_insert(BeaconSignerSeat::vacant());
        // A fresh fence resumes from the durable ratify record, so a
        // restarted process agrees with its own pre-crash signatures —
        // the coordinator's recovered registers refuse the same
        // positions, and this keeps the two guards aligned.
        if seat.max_ratify.is_none() {
            seat.max_ratify = self
                .beacon_storage
                .ratify_record(validator)
                .and_then(|record| record.max_position());
        }
        let allowed = seat.allow_ratify(position);
        drop(seats);
        allowed
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
    /// If no hosted shard is touched, returns
    /// [`SubmitFanout::GossipOnly`] — gossip still goes out via some
    /// hosted shard, but no shard admits or takes ownership.
    pub(crate) fn compute_submit_fanout(&self, tx: &Transaction) -> SubmitFanout {
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
            let instances = error.unresolved().to_vec();
            if !instances.is_empty()
                && let Some(host) = self.shard_event_senders.load().keys().copied().next()
            {
                return SubmitFanout::WantsRecords { host, instances };
            }
            tracing::warn!(
                reason = %error,
                "Dropping locally-submitted transaction: it derives no routing"
            );
            return SubmitFanout::Underivable;
        }
        let topology_snapshot = self.topology_snapshot.load();
        let touched_shards: Vec<ShardId> = topology_snapshot.all_shards_for_transaction(tx);

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
            SubmitFanout::WantsRecords { host, instances } => {
                let env = HostEvent::shard(
                    host,
                    ShardScopedInput::InstanceRecordsWanted {
                        wanted: vec![DeferredTransaction {
                            tx: Arc::clone(tx),
                            instances,
                            origin: DeferredOrigin::Submission,
                        }],
                    },
                );
                if self.shard_sender(host).send(env).is_err() {
                    ok = false;
                }
            }
            SubmitFanout::Underivable => ok = false,
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
        let payer_shard = topology.shard_trie().shard_for_prefix(tx.body().fee_payer);
        let handles = self.dispatch_handles.per_shard.load();
        let chain = &handles.get(&payer_shard)?.pending_chain;

        let view = chain.view_at_committed_tip();
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
                        &*self.verifier,
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
    /// Every hosted shard (and the pool) calls this as it folds the beacon,
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
    /// The envelope names components this node has not seen sealed, so
    /// it derives no routing yet and there is nothing to fan out to.
    ///
    /// A gap rather than a verdict: the seals committed on the shards
    /// owning their prefixes, and the envelope derives on any node that
    /// has them. It waits on `host` while that shard fetches the records.
    WantsRecords {
        /// A hosted shard to hold the envelope and run the fetch.
        host: ShardId,
        /// The component addresses its derivation could not resolve.
        instances: Vec<Address>,
    },
    /// The envelope's derivation refuses, so it names no shards to fan
    /// out to and there is nothing to gossip it on.
    ///
    /// Not necessarily the envelope's fault: derivation reads the
    /// package metadata this node holds, so a call to code the node has
    /// not installed refuses here and derives fine everywhere that has
    /// it. The maturity window is what makes that gap a startup
    /// condition rather than a standing one — a submission caught inside
    /// it is dropped and has to be offered again.
    Underivable,
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Epoch, ShardId, SpcView};

    use super::{BeaconSignerSeat, admit_topology_epoch};

    fn pos(epoch: u64, view: u32) -> (Epoch, SpcView) {
        (Epoch::new(epoch), SpcView::new(view))
    }

    /// The view claimant re-passes freely (phase progression, retries)
    /// while any other vnode is denied within the claimed view.
    #[test]
    fn view_claimant_re_passes_and_others_are_denied() {
        let mut seat = BeaconSignerSeat::vacant();
        let root = Some(ShardId::ROOT);
        let (left, right) = ShardId::ROOT.children();
        let (e, v) = pos(3, 1);

        assert!(
            seat.allow(root, e, v),
            "vacant fence: first dispatch claims"
        );
        assert!(
            seat.allow(root, e, v),
            "claimant re-emission within its view"
        );
        assert!(!seat.allow(Some(left), e, v), "same view, other vnode");
        assert!(!seat.allow(Some(right), e, v), "same view, third vnode");
        assert!(
            seat.allow(root, e, v),
            "claimant still passes after denials"
        );
    }

    /// The follower pool claims as `None`, a claimant distinct from every
    /// hosted shard — including `ShardId::ROOT`, a single-shard network's
    /// only leaf. A pooled follower and a `ROOT`-seated vnode of the same
    /// validator can therefore never both sign within one view.
    #[test]
    fn pool_claimant_never_aliases_a_root_seated_vnode() {
        let mut seat = BeaconSignerSeat::vacant();
        let (e, v) = pos(3, 1);

        assert!(seat.allow(Some(ShardId::ROOT), e, v), "seat claims");
        assert!(!seat.allow(None, e, v), "pool denied in the claimed view");

        let (_, v2) = pos(3, 2);
        assert!(seat.allow(None, e, v2), "pool claims the next view");
        assert!(
            !seat.allow(Some(ShardId::ROOT), e, v2),
            "seat denied in the pool's view"
        );
    }

    /// A strictly later view — same epoch or later epoch — transfers the
    /// claim to whichever vnode dispatches into it first; the old claimant
    /// is then denied at the transferred position.
    #[test]
    fn later_view_transfers_the_claim() {
        let mut seat = BeaconSignerSeat::vacant();
        let root = Some(ShardId::ROOT);
        let (left, _) = ShardId::ROOT.children();

        let (e, v1) = pos(3, 1);
        assert!(seat.allow(root, e, v1));

        // Next view within the epoch: the live sibling claims it.
        let (_, v2) = pos(3, 2);
        assert!(
            seat.allow(Some(left), e, v2),
            "sibling claims the next view"
        );
        assert!(
            !seat.allow(root, e, v2),
            "old claimant denied in the new view"
        );

        // Next epoch: claimable again by anyone.
        let (e4, v0) = pos(4, 0);
        assert!(seat.allow(root, e4, v0), "new epoch's proposal slot");
    }

    /// A dispatch for a view below the claimed one is regressive and denied
    /// regardless of which vnode asks — including the claimant itself.
    #[test]
    fn regressive_view_is_denied() {
        let mut seat = BeaconSignerSeat::vacant();
        let root = Some(ShardId::ROOT);
        let (left, _) = ShardId::ROOT.children();

        let (e, v2) = pos(3, 2);
        assert!(seat.allow(root, e, v2));

        let (_, v1) = pos(3, 1);
        assert!(!seat.allow(root, e, v1), "claimant regressing");
        assert!(!seat.allow(Some(left), e, v1), "sibling regressing");

        let (e2, v9) = pos(2, 9);
        assert!(!seat.allow(Some(left), e2, v9), "older epoch, any view");
    }

    /// The proposal slot (view zero) precedes view one, so an epoch's
    /// proposal is claimable before its first vote and a vote claim fences
    /// a late proposal of the same epoch.
    #[test]
    fn proposal_slot_orders_before_the_first_view() {
        let mut seat = BeaconSignerSeat::vacant();
        let root = Some(ShardId::ROOT);
        let (left, _) = ShardId::ROOT.children();

        let (e, v0) = pos(5, 0);
        let (_, v1) = pos(5, 1);
        assert!(seat.allow(root, e, v0), "proposal claims view zero");
        assert!(seat.allow(Some(left), e, v1), "vote view claimable after");
        assert!(!seat.allow(root, e, v0), "proposal slot now regressive");
    }

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
