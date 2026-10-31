//! The supervisor's reshape half: drive the sans-io `ReshapeOrchestrator`
//! and perform the io it requests against the real backends.
//!
//! [`ShardSupervisor::reshape_step`] feeds io results back, lets the
//! orchestrator re-discover this host's duties from the committed topology
//! projection, and dispatches the requests it returns — store opens and
//! seeds off the loop, fetches on the network, imports, applies, and adopts
//! via `spawn_blocking`, seats through the membership path. Every completion
//! lands back on the runner's select loop as a [`SupervisorEvent::Reshape`]
//! and settles through the host's prepared stores.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;

use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_network_iroh::IrohNetwork;
use hyperscale_node::bootstrap::EngineBootstrap;
use hyperscale_node::reshape::{
    AdoptKind, DerivedGenesis, FetchKind, FetchedKind, OverRunning, ReshapeCompletion,
    ReshapeEvent, ReshapeOrchestrator, ReshapeRequest, ReshapeView, Seating, Ticket,
    adopt_prepared_store, block_verdict, headers_verdict, ready_notification, seed_gate,
};
use hyperscale_node::{serve_local_certified_headers, serve_state_range_request};
use hyperscale_storage::{
    BoundaryStore, ImportProgress, RecoveredState, ShardChainReader, WitnessSeed,
};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::network::request::{
    GetBlockRequest, GetRemoteHeadersRequest, GetStateRangeRequest,
};
use hyperscale_types::network::response::{GetBlockResponse, GetRemoteHeadersResponse};
use hyperscale_types::{
    Block, BlockHeight, FrontierInputs, ReshapeSeat, ShardAnchor, ShardId, Signer, SubstateKey,
    SubstateLeaf, ValidatorId,
};
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::{ProdProcessIo, ShardSupervisor, StorageFactory, SupervisorEvent};
use crate::runner::wall_clock_local;

impl ShardSupervisor {
    /// The runner's reshape tick: pump the orchestrator with no completion,
    /// so a duty waiting on the clock — a deferred seed, a paced fetch —
    /// re-arms once its wait is out.
    pub(crate) fn reshape_tick(&mut self) {
        self.reshape_step(Vec::new());
    }

    /// Pump the reshape orchestrator one step: feed back the io results in
    /// `events`, let it re-discover this host's duties from the committed
    /// topology projection, and perform the io it returns. Idempotent; the
    /// runner pumps it from [`Self::reshape_tick`] and on every placement change.
    pub(crate) fn reshape_step(&mut self, events: Vec<ReshapeEvent>) {
        self.resume_pending_reshape_prep();
        let requests = {
            let schedule = self.process.topology_schedule();
            let view = ReshapeView::new(&schedule);
            self.reshape.step(
                &view,
                self.verifier.as_ref(),
                self.process.derivation().as_ref(),
                events,
                wall_clock_local(),
            )
        };
        for request in requests {
            self.dispatch_reshape(request);
        }
        // A store no live duty owns any more is dropped, releasing its
        // directory. A relinquished seat goes to the join now; a dropped
        // duty's shard is joined by the next `reconcile_seats`.
        let released = self
            .reshape_stores
            .release(|shard| self.reshape.is_seating(shard));
        for shard in released {
            self.hand_over_to_join(shard);
        }
    }

    /// Re-dispatch any reshape store-prep held behind an ordinary join whose
    /// open has now landed, a teardown whose thread has joined — its
    /// `bootstrapping` or `draining` entry cleared — or an earlier prep of
    /// the same shard that has landed, so the duty opens the store now that
    /// nothing else holds the directory.
    pub(super) fn resume_pending_reshape_prep(&mut self) {
        for request in self
            .reshape_stores
            .ready_preps(|shard, ticket| self.reshape.awaits(shard, ticket))
        {
            self.dispatch_reshape(request);
        }
        for shard in self.seats.ready_preps() {
            let Some(request) = self.seats.take_prep(shard) else {
                continue;
            };
            // The reshape that requested this prep may have been cancelled while
            // it was held; drop the held prep rather than opening a store no
            // duty will seat.
            if reshape_owns(&self.reshape, &self.process, &self.vnode_keys, shard) {
                self.dispatch_reshape(request);
            }
        }
    }

    /// Perform one reshape io request, answering with a
    /// [`SupervisorEvent::Reshape`] the runner loop settles through
    /// [`Self::on_reshape_io`].
    fn dispatch_reshape(&mut self, request: ReshapeRequest) {
        // A store-prep for a shard an ordinary join is still opening is held
        // until that join's open lands and is abandoned (`on_opened` ->
        // `reshape_owns`), and one for a shard still draining until its
        // thread joins (`on_torn_down`), so the prep's wipe never touches a
        // `RocksDB` directory another store holds open. Resumed from
        // `resume_pending_reshape_prep`.
        let store_shard = request.prepared_shard();
        if let Some(shard) = store_shard
            && self.seats.holds_store_dir(shard)
        {
            info!(shard = ?shard, "Reshape store-prep held behind an in-flight join or teardown");
            self.seats.hold_prep(shard, request);
            return;
        }
        // A running target's directory is that loop's live store and is
        // never wiped.
        if let Some(shard) = store_shard
            && self.seats.is_running(shard)
        {
            info!(shard = ?shard, "Reshape store-prep for a shard already running here; its store stays");
            if let Some(OverRunning::Answer(event)) = request.over_running() {
                self.on_reshape_io(ReshapeCompletion::Event(event));
            }
            return;
        }
        // A prep of a shard whose earlier prep is still off the loop waits
        // for that one to land, and an admitted prep closes the store an
        // earlier duty prepared, before either wipes the directory.
        let Some(request) = self.reshape_stores.prep(request) else {
            return;
        };
        match request {
            ReshapeRequest::OpenStore { shard, ticket } => self.reshape_open_store(shard, ticket),
            ReshapeRequest::SeedFromParent {
                parent,
                child,
                through,
                ticket,
            } => self.reshape_seed_from_parent(parent, child, through, ticket),
            ReshapeRequest::Fetch { duty, from, kind } => self.reshape_fetch(duty, from, kind),
            ReshapeRequest::StageChunk {
                shard,
                progress,
                leaves,
                ticket,
            } => self.reshape_stage(shard, progress, leaves, ticket),
            ReshapeRequest::FinalizeImport {
                shard,
                height,
                ticket,
            } => self.reshape_finalize(shard, height, ticket),
            ReshapeRequest::ApplyFollow {
                shard,
                block,
                creations,
                frontier,
                ticket,
            } => self.reshape_apply(shard, block, creations, frontier, ticket),
            ReshapeRequest::BroadcastReady {
                validator,
                child,
                anchor,
                recipients,
            } => self.reshape_broadcast(validator, child, anchor, &recipients),
            ReshapeRequest::Adopt {
                shard,
                kind,
                genesis,
                ticket,
            } => self.reshape_adopt(shard, kind, *genesis, ticket),
            ReshapeRequest::Seat { shard } => self.reshape_seat(shard),
        }
    }

    /// Open (wiping any stale directory) a reshape duty's store off the
    /// loop, replicating the engine bootstrap into the fresh store, and
    /// answer with [`ReshapeCompletion::Opened`]. A failed open logs,
    /// strands the duty, and answers [`ReshapeCompletion::Failed`].
    fn reshape_open_store(&self, shard: ShardId, ticket: Ticket) {
        let factory = Arc::clone(&self.storage_factory);
        let engine_bootstrap = self.engine_bootstrap.clone();
        let dir = (self.storage_dir)(shard);
        let events = self.events_tx.clone();
        spawn_store_job(
            &self.tokio_handle,
            &self.events_tx,
            shard,
            ticket,
            move || {
                let outcome = open_fresh_store(&dir, shard, &factory, &engine_bootstrap);
                send_opened(&events, shard, ticket, outcome);
            },
        );
    }

    /// Seed a parent half's `child` store by checkpoint-cloning the host's own
    /// retained `parent` store onto the child subtree, once [`seed_gate`]
    /// passes: that parent chain has committed through the terminal crossing.
    /// Answers with [`ReshapeCompletion::Opened`] when the clone lands, or
    /// with the gate's event. The gate reads the parent's height inside the blocking
    /// task, so no store read runs on the loop. The checkpoint hard-links, so
    /// the clone shares the engine bootstrap and the parent's substates
    /// without copying.
    fn reshape_seed_from_parent(
        &self,
        parent: ShardId,
        child: ShardId,
        through: BlockHeight,
        ticket: Ticket,
    ) {
        let events = self.events_tx.clone();
        let parent_storage = self
            .storages
            .lock()
            .expect("storages lock")
            .get(&parent)
            .cloned();
        let Some(parent_storage) = parent_storage else {
            if let Some(event) = seed_gate(None, child, through, ticket) {
                let _ = events.send(SupervisorEvent::Reshape(ReshapeCompletion::Event(event)));
            }
            return;
        };
        let factory = Arc::clone(&self.storage_factory);
        let dir = (self.storage_dir)(child);
        spawn_store_job(
            &self.tokio_handle,
            &self.events_tx,
            child,
            ticket,
            move || {
                if let Some(event) = seed_gate(
                    Some(parent_storage.committed_height()),
                    child,
                    through,
                    ticket,
                ) {
                    let _ = events.send(SupervisorEvent::Reshape(ReshapeCompletion::Event(event)));
                    return;
                }
                let outcome = (|| -> Result<(Arc<RocksDbShardStorage>, RecoveredState), String> {
                    if dir.exists() {
                        std::fs::remove_dir_all(&dir)
                            .map_err(|e| format!("stale child store wipe: {e}"))?;
                    }
                    parent_storage
                        .checkpoint_into(&dir)
                        .map_err(|e| format!("child checkpoint: {e}"))?;
                    let storage = factory(&dir, child)?;
                    let recovered = storage.load_recovered_state(child);
                    Ok((storage, recovered))
                })();
                send_opened(&events, child, ticket, outcome);
            },
        );
    }

    /// Issue one reshape fetch against `from`'s committee, answering with
    /// [`ReshapeEvent::Fetched`] on success or [`ReshapeEvent::FetchFailed`]
    /// on a transport error. `from` resolves to its committee through the live
    /// topology.
    fn reshape_fetch(&self, duty: ShardId, from: ShardId, kind: FetchKind) {
        let events = self.events_tx.clone();
        match kind {
            FetchKind::StateRange { sub_range, request } => {
                // A merge keeper co-hosts the terminating halves it collects, so
                // serve their ranges from the local store: a half's committee
                // dissolves at the merge boundary, and a network fetch would just
                // hammer the drained shard's torn-down request protocol.
                let local = self
                    .storages
                    .lock()
                    .expect("storages lock")
                    .get(&from)
                    .cloned();
                let Some(storage) = local else {
                    Self::network_state_range(
                        self.process.network(),
                        &events,
                        duty,
                        from,
                        sub_range,
                        request,
                    );
                    return;
                };
                let network = Arc::clone(self.process.network());
                self.tokio_handle.spawn_blocking(move || {
                    let response = serve_state_range_request(&storage, &request);
                    if response.chunk.is_some() {
                        send_event(
                            &events,
                            ReshapeEvent::Fetched {
                                duty,
                                from,
                                kind: FetchedKind::StateRange {
                                    sub_range,
                                    response: Box::new(response),
                                },
                            },
                        );
                    } else {
                        // The local store no longer pins the boundary; fall back
                        // to the shard's committee.
                        Self::network_state_range(
                            &network, &events, duty, from, sub_range, request,
                        );
                    }
                });
            }
            FetchKind::Headers { request } => {
                // A recognition walk reads its own chain: a parent half is a
                // member of the parent it walks, and a merge keeper co-hosts
                // the child it runs. Serve those from the local store rather
                // than asking the network for blocks this host already holds
                // — and, for a shard whose committee dissolves at the cut,
                // rather than asking a committee that may already be gone.
                let local = self
                    .storages
                    .lock()
                    .expect("storages lock")
                    .get(&from)
                    .cloned();
                let Some(storage) = local else {
                    Self::network_headers(self.process.network(), &events, duty, from, request);
                    return;
                };
                self.tokio_handle.spawn_blocking(move || {
                    let response = serve_local_certified_headers(storage.as_ref(), &request);
                    send_event(
                        &events,
                        ReshapeEvent::Fetched {
                            duty,
                            from,
                            kind: FetchedKind::Headers {
                                response: Box::new(response),
                            },
                        },
                    );
                });
            }
            FetchKind::Block { request } => {
                let asked = request.clone();
                self.process.network().request(
                    from,
                    None,
                    request,
                    None,
                    Box::new(move |result| {
                        let (event, verdict) = block_answer(duty, from, asked, result);
                        send_event(&events, event);
                        verdict
                    }),
                );
            }
        }
    }

    /// Request a certified-header batch from `from`'s committee. The
    /// fallback when the walked shard isn't co-hosted locally — a merge
    /// keeper's sibling child.
    fn network_headers(
        network: &Arc<IrohNetwork>,
        events: &mpsc::UnboundedSender<SupervisorEvent>,
        duty: ShardId,
        from: ShardId,
        request: GetRemoteHeadersRequest,
    ) {
        let asked = request.clone();
        let events = events.clone();
        network.request(
            from,
            None,
            request,
            None,
            Box::new(move |result| {
                let (event, verdict) = headers_answer(duty, from, asked, result);
                send_event(&events, event);
                verdict
            }),
        );
    }

    /// Request one reshape state range from `from`'s committee, answering with a
    /// [`ReshapeEvent`]. The fallback when a duty's source isn't co-hosted locally.
    fn network_state_range(
        network: &Arc<IrohNetwork>,
        events: &mpsc::UnboundedSender<SupervisorEvent>,
        duty: ShardId,
        from: ShardId,
        sub_range: usize,
        request: GetStateRangeRequest,
    ) {
        let on_fail = request.clone();
        let events = events.clone();
        network.request(
            from,
            None,
            request,
            None,
            Box::new(move |result| {
                let event = result.map_or_else(
                    |_| ReshapeEvent::FetchFailed {
                        duty,
                        from,
                        kind: FetchKind::StateRange {
                            sub_range,
                            request: on_fail,
                        },
                    },
                    |response| ReshapeEvent::Fetched {
                        duty,
                        from,
                        kind: FetchedKind::StateRange {
                            sub_range,
                            response: Box::new(response),
                        },
                    },
                );
                send_event(&events, event);
                ResponseVerdict::Accept
            }),
        );
    }

    /// Durably stage one verified chunk into a reshape duty's store off
    /// the loop, answering with [`ReshapeEvent::Staged`] — or handing the
    /// chunk back via [`ReshapeEvent::StageFailed`] so the duty re-stages it
    /// instead of waiting forever on an ack that will never come.
    fn reshape_stage(
        &mut self,
        shard: ShardId,
        progress: ImportProgress,
        leaves: Vec<SubstateLeaf>,
        ticket: Ticket,
    ) {
        let Some(storage) = self.reshape_stores.lease(shard, ticket).map(Arc::clone) else {
            warn!(shard = ?shard, "Reshape stage for an unopened store; re-queued");
            send_event(
                &self.events_tx,
                ReshapeEvent::StageFailed {
                    shard,
                    progress,
                    leaves,
                    ticket,
                },
            );
            return;
        };
        let events = self.events_tx.clone();
        spawn_store_job(
            &self.tokio_handle,
            &self.events_tx,
            shard,
            ticket,
            move || {
                let staged = storage.stage_import_chunk(&progress, &leaves);
                // The handle closes before the completion frees the directory.
                drop(storage);
                match staged {
                    Ok(()) => send_event(&events, ReshapeEvent::Staged { shard, ticket }),
                    Err(error) => {
                        warn!(shard = ?shard, %error, "Reshape chunk staging failed; re-queued");
                        send_event(
                            &events,
                            ReshapeEvent::StageFailed {
                                shard,
                                progress,
                                leaves,
                                ticket,
                            },
                        );
                    }
                }
            },
        );
    }

    /// Build a reshape duty's boundary state from its staged chunks off
    /// the loop, answering with [`ReshapeEvent::Imported`], or with
    /// [`ReshapeCompletion::Failed`] when the import fails.
    fn reshape_finalize(&mut self, shard: ShardId, height: BlockHeight, ticket: Ticket) {
        let Some(storage) = self.reshape_stores.lease(shard, ticket).map(Arc::clone) else {
            warn!(shard = ?shard, "Reshape finalize for an unopened store; dropped");
            return;
        };
        let events = self.events_tx.clone();
        spawn_store_job(
            &self.tokio_handle,
            &self.events_tx,
            shard,
            ticket,
            move || {
                let imported = storage.finalize_boundary_import(height, WitnessSeed::default());
                drop(storage);
                match imported {
                    Ok(root) => send_event(
                        &events,
                        ReshapeEvent::Imported {
                            shard,
                            root,
                            ticket,
                        },
                    ),
                    Err(error) => {
                        warn!(shard = ?shard, %error, "Reshape boundary import failed");
                        send_failed(&events, shard, ticket);
                    }
                }
            },
        );
    }

    /// Apply a followed parent block's writes into a reshape duty's store
    /// off the loop, answering with [`ReshapeEvent::Applied`], or with
    /// [`ReshapeCompletion::Failed`] when the application fails.
    fn reshape_apply(
        &mut self,
        shard: ShardId,
        block: Arc<Block>,
        creations: Vec<(SubstateKey, Vec<u8>)>,
        frontier: FrontierInputs,
        ticket: Ticket,
    ) {
        let Some(storage) = self.reshape_stores.lease(shard, ticket).map(Arc::clone) else {
            warn!(shard = ?shard, "Reshape follow apply for an unopened store; dropped");
            return;
        };
        let events = self.events_tx.clone();
        spawn_store_job(
            &self.tokio_handle,
            &self.events_tx,
            shard,
            ticket,
            move || {
                let applied = storage.follow_block_writes(&block, &creations, &frontier);
                drop(storage);
                match applied {
                    Ok(root) => send_event(
                        &events,
                        ReshapeEvent::Applied {
                            shard,
                            root,
                            ticket,
                        },
                    ),
                    Err(error) => {
                        warn!(shard = ?shard, %error, "Reshape follow apply failed");
                        send_failed(&events, shard, ticket);
                    }
                }
            },
        );
    }

    /// Sign `validator`'s ready signal attesting the sync of `child`,
    /// anchored at `anchor`, and notify the reshape committee `recipients`.
    /// No response — the orchestrator re-asserts each step until the gate
    /// fires.
    fn reshape_broadcast(
        &self,
        validator: ValidatorId,
        child: ShardId,
        anchor: ShardAnchor,
        recipients: &[ValidatorId],
    ) {
        if let Some(notification) = ready_notification(
            &self.beacon_network,
            validator,
            child,
            self.vnode_keys.get(&validator).map(AsRef::as_ref),
            anchor,
            self.epoch_duration_ms,
        ) {
            self.process.network().notify(recipients, &notification);
        }
    }

    /// Adopt a reshape duty's derived genesis off the loop via the shared
    /// [`adopt_prepared_store`] gate, answering with
    /// [`ReshapeCompletion::Adopted`], which carries the genesis back for the
    /// seat; a gate failure logs, strands the duty (the seat never fires),
    /// and answers [`ReshapeCompletion::Failed`].
    fn reshape_adopt(
        &mut self,
        shard: ShardId,
        kind: AdoptKind,
        genesis: DerivedGenesis,
        ticket: Ticket,
    ) {
        let Some(storage) = self.reshape_stores.lease(shard, ticket).map(Arc::clone) else {
            warn!(shard = ?shard, "Reshape adopt for an unopened store; dropped");
            return;
        };
        let events = self.events_tx.clone();
        spawn_store_job(
            &self.tokio_handle,
            &self.events_tx,
            shard,
            ticket,
            move || {
                let adopted = adopt_prepared_store(storage.as_ref(), shard, kind, &genesis);
                drop(storage);
                match adopted {
                    Ok(recovered) => {
                        let _ = events.send(SupervisorEvent::Reshape(ReshapeCompletion::Adopted {
                            shard,
                            genesis: Box::new(genesis.block),
                            recovered,
                            ticket,
                        }));
                    }
                    Err(error) => {
                        warn!(shard = ?shard, error, "Reshape adoption failed; duty stranded");
                        send_failed(&events, shard, ticket);
                    }
                }
            },
        );
    }

    /// Seat a prepared reshape duty: install its derived genesis and start
    /// consensus for every local committee member of `shard`, from the
    /// store the duty adopted into. The orchestrator owns this seating, so
    /// an ordinary join for the same shard is suppressed.
    fn reshape_seat(&mut self, shard: ShardId) {
        let draining = self.seats.is_draining(shard);
        debug_assert!(
            !draining || !self.reshape_stores.contains(shard),
            "a store is prepared for {shard:?} while its torn down loop drains",
        );
        let hosted = self.seats.is_running(shard) || draining;
        let Some(Seating {
            storage,
            genesis,
            recovered,
        }) = self.reshape_stores.take_for_seat(shard, hosted)
        else {
            return;
        };
        // No join is bootstrapping a shard with a prepared store: a prep
        // issued while a join is in flight is held behind it, and a prepared
        // store suppresses any later join (`join` reads `reshape_stores`).
        debug_assert!(
            !self.seats.is_bootstrapping(shard),
            "a join is bootstrapping {shard:?} under its reshape seat",
        );
        let topology_snapshot = self.process.topology_snapshot().load_full();
        let vnodes = self.local_committee_vnodes(&topology_snapshot, shard);
        if vnodes.is_empty() {
            warn!(shard = ?shard, "Reshape seat with no local committee members; dropped");
            return;
        }
        self.seat_shard_with_genesis(shard, &vnodes, storage, &recovered, Some(&genesis));
    }

    /// Settle one reshape completion through the prepared stores and pump
    /// the event it answers back through [`Self::reshape_step`]. A seed with
    /// no parent store to clone relinquishes the child's seat, which the
    /// ordinary join then takes.
    pub(super) fn on_reshape_io(
        &mut self,
        completion: ReshapeCompletion<Arc<RocksDbShardStorage>>,
    ) {
        let Some(event) = self.reshape_stores.settle(completion, |shard, ticket| {
            self.reshape.awaits(shard, ticket)
        }) else {
            // A completion no duty takes may still have freed a directory a
            // held prep waits on.
            self.resume_pending_reshape_prep();
            return;
        };
        let unavailable = match event {
            ReshapeEvent::SeedUnavailable { child, .. } => Some(child),
            _ => None,
        };
        self.reshape_step(vec![event]);
        if let Some(child) = unavailable {
            self.hand_over_to_join(child);
        }
    }

    /// Join `child` through the ordinary membership path once its split duty
    /// relinquished the seat: snap-sync against its attested anchor, or park
    /// until this host's topology carries one. A store the duty prepared is
    /// dropped first, releasing its directory to the join, which wipes what
    /// the duty left there. With no local member placed on the child yet, the
    /// reshape tick's [`Self::reconcile_seats`] joins it once one is.
    fn hand_over_to_join(&mut self, child: ShardId) {
        if !self.reshape.relinquished(child) {
            return;
        }
        self.reshape_stores.remove(child);
        info!(
            shard = ?child,
            "Split duty relinquished the child's seat; joining it instead"
        );
        let topology_snapshot = self.process.topology_snapshot().load_full();
        let vnodes = self.local_committee_vnodes(&topology_snapshot, child);
        if !vnodes.is_empty() {
            self.join(child, &vnodes);
        }
    }
}

/// Whether a reshape duty on this host owns seating `shard` — one of the
/// host's validators holds a parent-half or observer seat for `shard` as a
/// split child, or a keeper seat reforming `shard` as a merge parent.
///
/// Read straight from the committed projection (the cohorts the beacon fold
/// published), so it answers before the orchestrator's discovery step
/// populates its own duty maps — the window in which an ordinary join would
/// otherwise race the reshape duty for the shard's store directory. A seat
/// the orchestrator relinquished to the join is not owned, cohort or not.
/// Takes the supervisor's fields apart so a join can ask it while its seat
/// table is borrowed.
pub(super) fn reshape_owns(
    reshape: &ReshapeOrchestrator,
    process: &ProdProcessIo,
    vnode_keys: &HashMap<ValidatorId, Arc<dyn Signer>>,
    shard: ShardId,
) -> bool {
    if reshape.relinquished(shard) {
        return false;
    }
    let schedule = process.topology_schedule();
    let view = ReshapeView::new(&schedule);
    host_reshape_owns(
        view.parent_half_cohorts(),
        view.observer_cohorts(),
        view.keeper_cohorts(),
        shard,
        |validator| vnode_keys.contains_key(validator),
    )
}

/// Send a reshape event back to the supervisor loop. Send failure means
/// the runner is shutting down.
fn send_event(events: &mpsc::UnboundedSender<SupervisorEvent>, event: ReshapeEvent) {
    let _ = events.send(SupervisorEvent::Reshape(ReshapeCompletion::Event(event)));
}

/// Wipe `dir` and open a fresh store for `shard` there, carrying the engine
/// bootstrap, with the state it recovers.
fn open_fresh_store(
    dir: &Path,
    shard: ShardId,
    factory: &StorageFactory,
    engine_bootstrap: &EngineBootstrap,
) -> Result<(Arc<RocksDbShardStorage>, RecoveredState), String> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|e| format!("stale reshape store wipe: {e}"))?;
    }
    let storage = factory(dir, shard)?;
    // The directory was just wiped, so the store is fresh: it must carry the
    // engine bootstrap on its substate side before the duty's child-span or
    // merged-union import, or the seated shard would lack the global engine
    // nodes (the transaction tracker, the consensus manager) every
    // transaction reads.
    engine_bootstrap.replicate_into(storage.as_ref());
    let recovered = storage.load_recovered_state(shard);
    Ok((storage, recovered))
}

/// Send a landed store open or seed back to the supervisor loop; a failed one
/// logs, strands the duty, and frees the shard's directory for the next prep.
fn send_opened(
    events: &mpsc::UnboundedSender<SupervisorEvent>,
    shard: ShardId,
    ticket: Ticket,
    outcome: Result<(Arc<RocksDbShardStorage>, RecoveredState), String>,
) {
    match outcome {
        Ok((storage, recovered)) => {
            // Send failure means the runner is shutting down.
            let _ = events.send(SupervisorEvent::Reshape(ReshapeCompletion::Opened {
                shard,
                storage,
                recovered,
                ticket,
            }));
        }
        Err(error) => {
            warn!(shard = ?shard, error, "Reshape store open failed; duty stranded");
            send_failed(events, shard, ticket);
        }
    }
}

/// Run the reshape store prep or store job `ticket` names off the loop. One
/// that panics answers [`ReshapeCompletion::Failed`] once its unwinding has
/// dropped everything it held, so its hold on `shard`'s directory ends.
fn spawn_store_job(
    tokio_handle: &TokioHandle,
    events: &mpsc::UnboundedSender<SupervisorEvent>,
    shard: ShardId,
    ticket: Ticket,
    job: impl FnOnce() + Send + 'static,
) {
    let job = tokio_handle.spawn_blocking(job);
    let events = events.clone();
    tokio_handle.spawn(async move {
        if let Err(error) = job.await {
            warn!(shard = ?shard, %error, "Reshape store job did not finish; duty stranded");
            send_failed(&events, shard, ticket);
        }
    });
}

/// Send a failed reshape store prep or store job back to the supervisor
/// loop, releasing its hold on `shard`'s directory.
fn send_failed(events: &mpsc::UnboundedSender<SupervisorEvent>, shard: ShardId, ticket: Ticket) {
    let _ = events.send(SupervisorEvent::Reshape(ReshapeCompletion::Failed {
        shard,
        ticket,
    }));
}

/// Whether a reshape duty staffed by one of the host's `owned` validators owns
/// seating `shard` — a parent-half or observer seat for a split child, or a
/// keeper seat reforming a merge parent.
///
/// Keyed as the beacon projection publishes the cohorts: parent-halves by the
/// child each member seats on, observers by the splitting parent (mapping each
/// observer to the child it syncs), keepers by the child each runs (mapping to
/// the parent it reforms). So `shard` is owned as a split child via the first
/// two and as a merge parent via the third.
fn host_reshape_owns(
    parent_half_cohorts: &BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    observer_cohorts: &BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>>,
    keeper_cohorts: &BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>>,
    shard: ShardId,
    owned: impl Fn(&ValidatorId) -> bool,
) -> bool {
    if parent_half_cohorts
        .get(&shard)
        .is_some_and(|seats| seats.keys().any(&owned))
    {
        return true;
    }
    [observer_cohorts, keeper_cohorts]
        .into_iter()
        .any(|cohorts| {
            cohorts.values().any(|seats| {
                seats
                    .iter()
                    .any(|(v, seat)| seat.shard == shard && owned(v))
            })
        })
}

/// A reshape block fetch's result as the event its duty consumes, and the
/// verdict the transport scores the serving peer by.
///
/// Every answer reaches the duty, which judges it again against what it
/// holds; the verdict is what the request alone decides. A transport
/// failure is already on the peer's record, so it scores nothing further.
fn block_answer(
    duty: ShardId,
    from: ShardId,
    asked: GetBlockRequest,
    result: Result<GetBlockResponse, RequestError>,
) -> (ReshapeEvent, ResponseVerdict) {
    let Ok(response) = result else {
        let kind = FetchKind::Block { request: asked };
        return (
            ReshapeEvent::FetchFailed { duty, from, kind },
            ResponseVerdict::Accept,
        );
    };
    let verdict = block_verdict(&asked, &response);
    let kind = FetchedKind::Block {
        response: Box::new(response),
    };
    (ReshapeEvent::Fetched { duty, from, kind }, verdict)
}

/// [`block_answer`] for a recognition walk's certified-header fetch.
fn headers_answer(
    duty: ShardId,
    from: ShardId,
    asked: GetRemoteHeadersRequest,
    result: Result<GetRemoteHeadersResponse, RequestError>,
) -> (ReshapeEvent, ResponseVerdict) {
    let Ok(response) = result else {
        let kind = FetchKind::Headers { request: asked };
        return (
            ReshapeEvent::FetchFailed { duty, from, kind },
            ResponseVerdict::Accept,
        );
    };
    let verdict = headers_verdict(&asked, &response);
    let kind = FetchedKind::Headers {
        response: Box::new(response),
    };
    (ReshapeEvent::Fetched { duty, from, kind }, verdict)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use hyperscale_engine::GenesisConfig;
    use hyperscale_hbor::Capped;
    use hyperscale_network::{RequestError, ResponseVerdict};
    use hyperscale_node::bootstrap::EngineBootstrap;
    use hyperscale_node::reshape::{
        FetchedKind, PreparedStores, ReshapeCompletion, ReshapeEvent, ReshapeRequest, Ticket,
    };
    use hyperscale_storage::test_helpers::make_test_block;
    use hyperscale_storage_rocksdb::RocksDbShardStorage;
    use hyperscale_types::network::request::{
        BlockIntent, GetBlockRequest, GetRemoteHeadersRequest, MAX_REMOTE_HEADERS_PER_REQUEST,
    };
    use hyperscale_types::network::response::{GetBlockResponse, GetRemoteHeadersResponse};
    use hyperscale_types::test_utils::{TestCommittee, signed_child_block};
    use hyperscale_types::{
        Block, BlockHeight, CertifiedBlockHeader, ElidedCertifiedBlock, Inventory, Round, ShardId,
        ValidatorId, WeightedTimestamp, shard_prefix_path,
    };
    use tempfile::TempDir;
    use tokio::runtime::Runtime;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::{
        ReshapeSeat, StorageFactory, SupervisorEvent, block_answer, headers_answer,
        host_reshape_owns, open_fresh_store, spawn_store_job,
    };

    /// Two blocks of one parent chain above height 1, their QCs signed by
    /// `committee`.
    fn parent_chain(committee: &TestCommittee) -> (Block, Block) {
        let base = make_test_block(BlockHeight::new(1));
        let b2 = signed_child_block(
            committee,
            &base,
            Round::new(2),
            WeightedTimestamp::from_millis(100),
        );
        let b3 = signed_child_block(
            committee,
            &b2,
            Round::new(3),
            WeightedTimestamp::from_millis(200),
        );
        (b2, b3)
    }

    fn certified(committee: &TestCommittee, block: &Block) -> CertifiedBlockHeader {
        CertifiedBlockHeader::new(
            block.header().clone(),
            committee.sign_qc(
                block.header(),
                &committee.quorum_indices(),
                WeightedTimestamp::from_millis(900),
            ),
        )
    }

    /// A block answer the request refuses scores the peer that served it,
    /// and still reaches the duty; one that holds nothing yet, or a failed
    /// transfer, does not score it.
    #[test]
    fn a_refused_block_answer_is_rejected() {
        let committee = TestCommittee::new(4, 3);
        let (b2, b3) = parent_chain(&committee);
        let asked = GetBlockRequest::new(BlockHeight::new(2), BlockIntent::Execute);
        let served = |block: &Block| {
            let qc = certified(&committee, block).qc().clone();
            Ok(GetBlockResponse::found(ElidedCertifiedBlock::elide(
                block,
                qc,
                &Inventory::empty(),
            )))
        };
        let answer = |result| block_answer(ShardId::ROOT, ShardId::ROOT, asked.clone(), result);

        let (event, verdict) = answer(served(&b3));
        assert_eq!(verdict, ResponseVerdict::Reject, "a block off the height");
        assert!(matches!(
            event,
            ReshapeEvent::Fetched {
                kind: FetchedKind::Block { .. },
                ..
            }
        ));
        assert_eq!(answer(served(&b2)).1, ResponseVerdict::Accept);
        assert_eq!(
            answer(Ok(GetBlockResponse::not_found())).1,
            ResponseVerdict::Accept,
            "a height nothing holds yet is an honest answer",
        );
        let (event, verdict) = answer(Err(RequestError::Timeout));
        assert_eq!(verdict, ResponseVerdict::Accept);
        assert!(matches!(event, ReshapeEvent::FetchFailed { .. }));
    }

    #[test]
    fn a_refused_header_answer_is_rejected() {
        let committee = TestCommittee::new(4, 3);
        let (b2, b3) = parent_chain(&committee);
        let asked = GetRemoteHeadersRequest {
            source_shard: ShardId::ROOT,
            from_height: BlockHeight::new(2),
            count: MAX_REMOTE_HEADERS_PER_REQUEST,
        };
        let batch = |blocks: &[&Block]| {
            Ok(GetRemoteHeadersResponse::of(
                Capped::new(blocks.iter().map(|b| certified(&committee, b)).collect())
                    .expect("within one request"),
            ))
        };
        let answer = |result| headers_answer(ShardId::ROOT, ShardId::ROOT, asked.clone(), result);

        assert_eq!(
            answer(batch(&[&b3])).1,
            ResponseVerdict::Reject,
            "a run off the requested height",
        );
        assert_eq!(answer(batch(&[&b2, &b3])).1, ResponseVerdict::Accept);
        assert_eq!(
            answer(batch(&[])).1,
            ResponseVerdict::Accept,
            "an empty batch at the tip is an honest answer",
        );
    }

    const HOST: ValidatorId = ValidatorId::new(1);

    /// A cohort seat pairing the holder with `shard`. Ownership reads the
    /// pairing, never the readiness.
    const fn seat(shard: ShardId) -> ReshapeSeat {
        ReshapeSeat {
            shard,
            ready: false,
        }
    }

    /// A host whose validator holds a parent-half seat owns the split child —
    /// so an ordinary join for the child yields to the reshape duty.
    #[test]
    fn host_reshape_owns_a_split_child_via_parent_half() {
        let parent = ShardId::ROOT;
        let child = ShardId::leaf(1, 0);
        let parent_halves = BTreeMap::from([(child, BTreeMap::from([(HOST, parent)]))]);
        assert!(host_reshape_owns(
            &parent_halves,
            &BTreeMap::new(),
            &BTreeMap::new(),
            child,
            |v| *v == HOST,
        ));
    }

    /// An observer seat — keyed by the splitting parent, mapping to the child —
    /// also makes the host own the split child.
    #[test]
    fn host_reshape_owns_a_split_child_via_observer() {
        let parent = ShardId::ROOT;
        let child = ShardId::leaf(1, 0);
        let observers = BTreeMap::from([(parent, BTreeMap::from([(HOST, seat(child))]))]);
        assert!(host_reshape_owns(
            &BTreeMap::new(),
            &observers,
            &BTreeMap::new(),
            child,
            |v| *v == HOST,
        ));
    }

    /// A keeper seat — keyed by the child it runs, mapping to the reformed
    /// parent — makes the host own the merge parent.
    #[test]
    fn host_reshape_owns_a_merge_parent_via_keeper() {
        let parent = ShardId::ROOT;
        let child = ShardId::leaf(1, 0);
        let keepers = BTreeMap::from([(child, BTreeMap::from([(HOST, seat(parent))]))]);
        assert!(host_reshape_owns(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &keepers,
            parent,
            |v| *v == HOST,
        ));
    }

    /// A cohort seat held by another host's validator is not owned here, and a
    /// shard with no cohort is not owned at all.
    #[test]
    fn host_reshape_owns_only_its_own_seats() {
        let parent = ShardId::ROOT;
        let child = ShardId::leaf(1, 0);
        let other = ValidatorId::new(99);
        let parent_halves = BTreeMap::from([(child, BTreeMap::from([(other, parent)]))]);
        assert!(!host_reshape_owns(
            &parent_halves,
            &BTreeMap::new(),
            &BTreeMap::new(),
            child,
            |v| *v == HOST,
        ));
        assert!(!host_reshape_owns(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            child,
            |v| *v == HOST,
        ));
    }

    /// Two opens of one shard's directory, the earlier still off the loop
    /// when the later is issued: the later waits until the earlier lands,
    /// and the earlier's store, which no duty awaits by then, is closed
    /// before the later wipes the directory. The store left prepared is
    /// the later one, which the orchestrator awaits.
    #[test]
    fn a_second_open_of_a_shard_never_wipes_under_a_live_store() {
        let dir = TempDir::new().expect("tempdir");
        let shard = ShardId::leaf(1, 0);
        let (factory, bootstrap) = (rocksdb_factory(), bare_bootstrap());
        let open = || open_fresh_store(dir.path(), shard, &factory, &bootstrap).expect("open");
        let (earlier, later) = (Ticket::new(3), Ticket::new(4));
        let awaits = |awaited, ticket| awaited == shard && ticket == later;
        let mut stores = PreparedStores::new();

        let first = stores
            .prep(ReshapeRequest::OpenStore {
                shard,
                ticket: earlier,
            })
            .expect("nothing else prepares the shard");
        assert!(matches!(first, ReshapeRequest::OpenStore { .. }));
        let (storage, recovered) = open();
        let live = Arc::downgrade(&storage);
        assert!(
            stores
                .prep(ReshapeRequest::OpenStore {
                    shard,
                    ticket: later,
                })
                .is_none(),
            "the later open waits while the earlier holds the directory",
        );
        assert!(stores.ready_preps(awaits).is_empty());

        let stale = stores.settle(
            ReshapeCompletion::Opened {
                shard,
                storage,
                recovered,
                ticket: earlier,
            },
            awaits,
        );
        assert!(stale.is_none(), "no duty awaits the earlier open");
        assert!(live.upgrade().is_none(), "the earlier store is closed");

        let ready = stores.ready_preps(awaits);
        let [request] = ready.as_slice() else {
            panic!("the later open is released once the earlier lands: {ready:?}");
        };
        assert!(stores.prep(request.clone()).is_some());
        let (storage, recovered) = open();
        let opened = Arc::downgrade(&storage);
        let event = stores.settle(
            ReshapeCompletion::Opened {
                shard,
                storage,
                recovered,
                ticket: later,
            },
            awaits,
        );
        assert!(matches!(event, Some(ReshapeEvent::Opened { ticket, .. }) if ticket == later));
        let kept = stores.storage(shard).expect("the later store is prepared");
        assert!(Arc::ptr_eq(kept, &opened.upgrade().expect("held")));
    }

    /// A store's job holds its own handle past the store leaving the map.
    /// A reopen of the shard issued meanwhile waits until the job ends,
    /// whose handle closes before its completion settles, so the reopen
    /// never wipes the directory under the job.
    #[test]
    fn a_reopen_never_wipes_under_a_running_job() {
        let dir = TempDir::new().expect("tempdir");
        let shard = ShardId::leaf(1, 0);
        let (factory, bootstrap) = (rocksdb_factory(), bare_bootstrap());
        let open = || open_fresh_store(dir.path(), shard, &factory, &bootstrap).expect("open");
        let (first, stage, reopen) = (Ticket::new(3), Ticket::new(4), Ticket::new(5));
        let awaits = |awaited, ticket| awaited == shard && (ticket == first || ticket == reopen);
        let mut stores = PreparedStores::new();

        assert!(
            stores
                .prep(ReshapeRequest::OpenStore {
                    shard,
                    ticket: first,
                })
                .is_some()
        );
        let (storage, recovered) = open();
        let opened = ReshapeCompletion::Opened {
            shard,
            storage,
            recovered,
            ticket: first,
        };
        assert!(stores.settle(opened, awaits).is_some());

        let job = Arc::clone(stores.lease(shard, stage).expect("the store is prepared"));
        assert_eq!(
            stores.release(|_| false),
            vec![shard],
            "the duty is dropped"
        );
        let live = Arc::downgrade(&job);
        assert!(live.upgrade().is_some(), "the job still holds the store");
        assert!(
            stores
                .prep(ReshapeRequest::OpenStore {
                    shard,
                    ticket: reopen,
                })
                .is_none(),
            "the reopen waits while the job holds the directory",
        );
        assert!(stores.ready_preps(awaits).is_empty());

        drop(job);
        let staged = ReshapeEvent::Staged {
            shard,
            ticket: stage,
        };
        let _ = stores.settle(ReshapeCompletion::Event(staged), awaits);
        let ready = stores.ready_preps(awaits);
        let [request] = ready.as_slice() else {
            panic!("the reopen is released once the job ends: {ready:?}");
        };
        assert!(stores.prep(request.clone()).is_some());
        assert!(live.upgrade().is_none(), "no handle outlives the job");
        let (storage, recovered) = open();
        let reopened = ReshapeCompletion::Opened {
            shard,
            storage,
            recovered,
            ticket: reopen,
        };
        assert!(stores.settle(reopened, awaits).is_some());
    }

    /// A store job that panics still answers, once its unwinding has closed
    /// the handle it held, so its hold on the shard's directory ends and a
    /// prep waiting behind it is released.
    #[test]
    fn a_panicking_store_job_still_ends_its_hold() {
        let runtime = Runtime::new().expect("runtime");
        let (events, mut answers) = mpsc::unbounded_channel();
        let dir = TempDir::new().expect("tempdir");
        let shard = ShardId::leaf(1, 0);
        let (open, apply, reopen) = (Ticket::new(3), Ticket::new(4), Ticket::new(5));
        let awaits = |awaited, ticket| awaited == shard && (ticket == open || ticket == reopen);
        let mut stores = PreparedStores::new();
        assert!(
            stores
                .prep(ReshapeRequest::OpenStore {
                    shard,
                    ticket: open
                })
                .is_some()
        );
        let (storage, recovered) =
            open_fresh_store(dir.path(), shard, &rocksdb_factory(), &bare_bootstrap())
                .expect("open");
        let opened = ReshapeCompletion::Opened {
            shard,
            storage,
            recovered,
            ticket: open,
        };
        assert!(stores.settle(opened, awaits).is_some());

        let job = Arc::clone(stores.lease(shard, apply).expect("the store is prepared"));
        let live = Arc::downgrade(&job);
        spawn_store_job(runtime.handle(), &events, shard, apply, move || {
            let _held = job;
            panic!("a store job panics");
        });
        assert_eq!(stores.release(|_| false), vec![shard]);
        assert!(
            stores
                .prep(ReshapeRequest::OpenStore {
                    shard,
                    ticket: reopen
                })
                .is_none()
        );

        let answer = runtime
            .block_on(async { timeout(Duration::from_secs(10), answers.recv()).await })
            .expect("the panicking job answers")
            .expect("the channel is open");
        let SupervisorEvent::Reshape(failed) = answer else {
            panic!("a store job answers with a reshape completion");
        };
        assert!(
            matches!(failed, ReshapeCompletion::Failed { shard: s, ticket } if s == shard && ticket == apply)
        );
        assert!(live.upgrade().is_none(), "the unwinding closed the handle");
        assert!(stores.settle(failed, awaits).is_none());
        assert_eq!(
            stores.ready_preps(awaits).len(),
            1,
            "the reopen is released"
        );
    }

    fn rocksdb_factory() -> StorageFactory {
        Arc::new(|dir, shard| {
            RocksDbShardStorage::open(dir, shard_prefix_path(shard))
                .map(Arc::new)
                .map_err(|e| e.to_string())
        })
    }

    fn bare_bootstrap() -> EngineBootstrap {
        EngineBootstrap {
            config: GenesisConfig::default(),
        }
    }
}
