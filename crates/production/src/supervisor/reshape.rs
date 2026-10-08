//! The supervisor's reshape half: drive the sans-io `ReshapeOrchestrator`
//! and perform the io it requests against the real backends.
//!
//! [`ShardSupervisor::reshape_step`] feeds io results back, lets the
//! orchestrator re-discover this host's duties from the committed topology
//! projection, and dispatches the requests it returns — store opens and
//! seeds off the loop, fetches on the network, imports, applies, and adopts
//! via `spawn_blocking`, seats through the membership path. Every completion
//! lands back on the runner's select loop as a
//! [`SupervisorEvent::Reshape`].

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_network_libp2p::Libp2pNetwork;
use hyperscale_node::reshape::PreparedStore;
use hyperscale_node::reshape::adopt::adopt_prepared_store;
use hyperscale_node::reshape::observer::observer_ready_signal;
use hyperscale_node::reshape::orchestrator::{
    AdoptKind, FetchKind, FetchedKind, ReshapeEvent, ReshapeRequest,
};
use hyperscale_node::reshape::screen::{block_verdict, headers_verdict};
use hyperscale_node::reshape::view::ReshapeView;
use hyperscale_node::{serve_local_certified_headers, serve_state_range_request};
use hyperscale_storage::{
    BoundaryStore, ImportProgress, RecoveredState, ShardChainReader, WitnessSeed,
};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::network::notification::ReadySignalNotification;
use hyperscale_types::network::request::{
    GetBlockRequest, GetRemoteHeadersRequest, GetStateRangeRequest,
};
use hyperscale_types::network::response::{GetBlockResponse, GetRemoteHeadersResponse};
use hyperscale_types::{
    Anchor, Block, BlockHeight, ChainOrigin, FrontierInputs, ReshapeSeat, ShardAnchor, ShardId,
    StateRoot, SubstateKey, SubstateLeaf, ValidatorId,
};
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::{ShardSupervisor, SupervisorEvent};
use crate::runner::wall_clock_local;

/// One reshape io result fed back into the orchestrator's pump. The io
/// callbacks (network responses, off-loop store work) push these onto the
/// supervisor's event channel; [`ShardSupervisor::on_reshape_io`] updates
/// the in-flight [`PreparedStore`] cache and translates each into the
/// orchestrator's [`ReshapeEvent`] — the layer the orchestrator's `step`
/// consumes, which carries no store handles of its own.
pub enum ReshapeIo {
    /// A reshape store open settled: the open store and its recovered
    /// state, cached for the duty, or the open failure.
    Opened {
        /// The duty's store shard.
        shard: ShardId,
        /// The opened store and recovered state, or the open failure.
        outcome: Result<(Arc<RocksDbShardStorage>, RecoveredState), String>,
    },
    /// A reshape fetch returned a response.
    Fetched {
        /// The duty the fetch belonged to.
        duty: ShardId,
        /// The shard the fetch addressed.
        from: ShardId,
        /// The response.
        kind: FetchedKind,
    },
    /// A reshape fetch failed at the transport level.
    FetchFailed {
        /// The duty the fetch belonged to.
        duty: ShardId,
        /// The shard the fetch addressed.
        from: ShardId,
        /// What failed, for re-arming.
        kind: FetchKind,
    },
    /// A staged chunk was durably written.
    Staged {
        /// The store shard.
        shard: ShardId,
    },
    /// A staged chunk's durable write failed; hands the chunk back for
    /// re-staging.
    StageFailed {
        /// The store shard.
        shard: ShardId,
        /// The assembly's progress after the chunk.
        progress: ImportProgress,
        /// The chunk's verified leaves.
        leaves: Vec<SubstateLeaf>,
    },
    /// A boundary import completed with the resulting store root.
    Imported {
        /// The store shard.
        shard: ShardId,
        /// The imported root.
        root: StateRoot,
    },
    /// A followed-block application completed with the resulting store
    /// root.
    Applied {
        /// The store shard.
        shard: ShardId,
        /// The applied root.
        root: StateRoot,
    },
    /// A genesis adoption settled (root already verified against the
    /// anchor); carries the recovered state the seat boots from.
    Adopted {
        /// The store shard.
        shard: ShardId,
        /// The recovered state rebuilt over the adopted genesis.
        recovered: RecoveredState,
    },
    /// A parent-half seed could not run yet — the local parent is still behind
    /// the terminal crossing — so the seed should be re-armed on the next
    /// reshape tick.
    SeedDeferred {
        /// The split child whose seed is deferred.
        child: ShardId,
    },
    /// A parent-half seed found no hosted parent store to clone, so the duty
    /// hands the child's seat to the ordinary join.
    SeedUnavailable {
        /// The split child whose seat is handed over.
        child: ShardId,
    },
}

impl ShardSupervisor {
    /// Whether a reshape duty on this host owns seating `shard` — one of the
    /// host's validators holds a parent-half or observer seat for `shard` as a
    /// split child, or a keeper seat reforming `shard` as a merge parent.
    ///
    /// Read straight from the committed projection (the cohorts the beacon fold
    /// published), so it answers before the orchestrator's discovery step
    /// populates its own duty maps — the window in which an ordinary join would
    /// otherwise race the reshape duty for the shard's store directory. A seat
    /// the orchestrator relinquished to the join is not owned, cohort or not.
    pub(super) fn reshape_owns(&self, shard: ShardId) -> bool {
        if self.reshape.relinquished(shard) {
            return false;
        }
        let schedule = self.process.topology_schedule();
        let view = ReshapeView::new(&schedule);
        host_reshape_owns(
            view.parent_half_cohorts(),
            view.observer_cohorts(),
            view.keeper_cohorts(),
            shard,
            |validator| self.vnode_keys.contains_key(validator),
        )
    }

    /// The runner's reshape tick: pump the orchestrator with the deferrals
    /// held for it, so a retry waits out the tick rather than re-running
    /// against a cause that stands.
    pub(crate) fn reshape_tick(&mut self) {
        let deferred = std::mem::take(&mut self.deferred_reshape_events);
        self.reshape_step(deferred);
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
        let relinquished: Vec<ShardId> = self
            .reshape_stores
            .keys()
            .copied()
            .filter(|&shard| self.reshape.relinquished(shard))
            .collect();
        for shard in relinquished {
            self.hand_over_to_join(shard);
        }
    }

    /// Re-dispatch any reshape store-prep held behind an ordinary join whose
    /// open has now landed — its `bootstrapping` entry cleared — so the duty
    /// opens the store now that nothing else holds the directory.
    pub(super) fn resume_pending_reshape_prep(&mut self) {
        let ready: Vec<ShardId> = self
            .pending_reshape_prep
            .keys()
            .copied()
            .filter(|shard| !self.bootstrapping.contains_key(shard))
            .collect();
        for shard in ready {
            // The reshape that requested this prep may have been cancelled while
            // it was held; drop the held prep rather than opening a store no
            // duty will seat.
            if !self.reshape_owns(shard) {
                self.pending_reshape_prep.remove(&shard);
                continue;
            }
            if let Some(request) = self.pending_reshape_prep.remove(&shard) {
                self.dispatch_reshape(request);
            }
        }
    }

    /// Perform one reshape io request, answering with a
    /// [`SupervisorEvent::Reshape`] the runner loop feeds back through
    /// [`Self::on_reshape_io`].
    fn dispatch_reshape(&mut self, request: ReshapeRequest) {
        // A store-prep for a shard an ordinary join is still opening is held
        // until that join's open lands and is abandoned (`on_opened` ->
        // `reshape_owns`), so the two never touch the same `RocksDB` directory
        // at once. Resumed from `resume_pending_reshape_prep`.
        let store_shard = match &request {
            ReshapeRequest::OpenStore { shard } => Some(*shard),
            ReshapeRequest::SeedFromParent { child, .. } => Some(*child),
            _ => None,
        };
        if let Some(shard) = store_shard
            && self.bootstrapping.contains_key(&shard)
        {
            info!(shard = ?shard, "Reshape store-prep held behind an in-flight join");
            self.pending_reshape_prep.insert(shard, request);
            return;
        }
        // A duty only ever prepares a store for a shard this host does not
        // run yet, so a running target is a duty rediscovered after a restart
        // that resumed the shard's loop: its directory is that loop's live
        // store and is never wiped. A parent half relinquishes its seat to the
        // join, which seats its members on the running loop.
        if let Some(shard) = store_shard
            && self.shards.contains_key(&shard)
        {
            info!(shard = ?shard, "Reshape store-prep for a shard already running here; its store stays");
            if let ReshapeRequest::SeedFromParent { child, .. } = request {
                self.on_reshape_io(ReshapeIo::SeedUnavailable { child });
            }
            return;
        }
        match request {
            ReshapeRequest::OpenStore { shard } => self.reshape_open_store(shard),
            ReshapeRequest::SeedFromParent {
                parent,
                child,
                through,
            } => {
                // The clone replaces the child's directory wholesale, so a
                // store an observer prepared there before it relinquished
                // the seat to this parent half is closed first.
                self.reshape_stores.remove(&child);
                self.reshape_seed_from_parent(parent, child, through);
            }
            ReshapeRequest::Fetch { duty, from, kind } => self.reshape_fetch(duty, from, kind),
            ReshapeRequest::StageChunk {
                shard,
                progress,
                leaves,
            } => self.reshape_stage(shard, progress, leaves),
            ReshapeRequest::FinalizeImport { shard, height } => {
                self.reshape_finalize(shard, height);
            }
            ReshapeRequest::ApplyFollow {
                shard,
                block,
                creations,
                frontier,
            } => self.reshape_apply(shard, block, creations, frontier),
            ReshapeRequest::BroadcastReady {
                validator,
                child,
                anchor,
                recipients,
            } => self.reshape_broadcast(validator, child, anchor, &recipients),
            ReshapeRequest::Adopt {
                shard,
                kind,
                origin,
                genesis,
                predecessors,
            } => self.reshape_adopt(shard, kind, origin, *genesis, predecessors),
            ReshapeRequest::Seat { shard } => self.reshape_seat(shard),
        }
    }

    /// Open (wiping any stale directory) a reshape duty's store off the
    /// loop, replicating the engine bootstrap into the fresh store, and
    /// answer with [`ReshapeIo::Opened`].
    fn reshape_open_store(&self, shard: ShardId) {
        let factory = Arc::clone(&self.storage_factory);
        let engine_bootstrap = self.engine_bootstrap.clone();
        let dir = (self.storage_dir)(shard);
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            let outcome = (|| -> Result<(Arc<RocksDbShardStorage>, RecoveredState), String> {
                if dir.exists() {
                    std::fs::remove_dir_all(&dir)
                        .map_err(|e| format!("stale reshape store wipe: {e}"))?;
                }
                let storage = factory(&dir, shard)?;
                // The directory was just wiped, so the store is fresh: it must
                // carry the engine bootstrap on its substate side before the
                // duty's child-span or merged-union import, or the seated shard
                // would lack the global engine nodes (the transaction tracker,
                // the consensus manager) every transaction reads.
                engine_bootstrap.replicate_into(storage.as_ref());
                let recovered = storage.load_recovered_state(shard);
                Ok((storage, recovered))
            })();
            // Send failure means the runner is shutting down.
            let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::Opened {
                shard,
                outcome,
            }));
        });
    }

    /// Seed a parent half's `child` store by checkpoint-cloning the host's own
    /// retained `parent` store onto the child subtree, once that parent chain
    /// has committed through the terminal crossing. Answers with
    /// [`ReshapeIo::Opened`] when the clone lands, [`ReshapeIo::SeedDeferred`]
    /// while the local parent is still behind, or [`ReshapeIo::SeedUnavailable`]
    /// when this host holds no parent store. The checkpoint hard-links, so the
    /// clone shares the engine bootstrap and the parent's substates without
    /// copying.
    fn reshape_seed_from_parent(&self, parent: ShardId, child: ShardId, through: BlockHeight) {
        let events = self.events_tx.clone();
        let parent_storage = self
            .storages
            .lock()
            .expect("storages lock")
            .get(&parent)
            .cloned();
        let Some(parent_storage) = parent_storage else {
            let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::SeedUnavailable {
                child,
            }));
            return;
        };
        let factory = Arc::clone(&self.storage_factory);
        let dir = (self.storage_dir)(child);
        self.tokio_handle.spawn_blocking(move || {
            // `through` is the child's genesis height; the parent commits one
            // block past its terminal (the coast certifying it), so the local
            // chain is ready for the clone once its tip reaches it.
            if parent_storage.committed_height() < through {
                let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::SeedDeferred { child }));
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
            // Send failure means the runner is shutting down.
            let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::Opened {
                shard: child,
                outcome,
            }));
        });
    }

    /// Issue one reshape fetch against `from`'s committee, answering with
    /// [`ReshapeIo::Fetched`] on success or [`ReshapeIo::FetchFailed`] on a
    /// transport error. `from` resolves to its committee through the live
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
                        let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::Fetched {
                            duty,
                            from,
                            kind: FetchedKind::StateRange {
                                sub_range,
                                response: Box::new(response),
                            },
                        }));
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
                    let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::Fetched {
                        duty,
                        from,
                        kind: FetchedKind::Headers {
                            response: Box::new(response),
                        },
                    }));
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
                        let (io, verdict) = block_answer(duty, from, asked, result);
                        let _ = events.send(SupervisorEvent::Reshape(io));
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
        network: &Arc<Libp2pNetwork>,
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
                let (io, verdict) = headers_answer(duty, from, asked, result);
                let _ = events.send(SupervisorEvent::Reshape(io));
                verdict
            }),
        );
    }

    /// Request one reshape state range from `from`'s committee, answering with a
    /// [`ReshapeIo`]. The fallback when a duty's source isn't co-hosted locally.
    fn network_state_range(
        network: &Arc<Libp2pNetwork>,
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
                let io = result.map_or_else(
                    |_| ReshapeIo::FetchFailed {
                        duty,
                        from,
                        kind: FetchKind::StateRange {
                            sub_range,
                            request: on_fail,
                        },
                    },
                    |response| ReshapeIo::Fetched {
                        duty,
                        from,
                        kind: FetchedKind::StateRange {
                            sub_range,
                            response: Box::new(response),
                        },
                    },
                );
                let _ = events.send(SupervisorEvent::Reshape(io));
                ResponseVerdict::Accept
            }),
        );
    }

    /// Durably stage one verified chunk into a reshape duty's store off
    /// the loop, answering with [`ReshapeIo::Staged`] — or handing the
    /// chunk back via [`ReshapeIo::StageFailed`] so the duty re-stages it
    /// instead of waiting forever on an ack that will never come.
    fn reshape_stage(&self, shard: ShardId, progress: ImportProgress, leaves: Vec<SubstateLeaf>) {
        let Some(storage) = self
            .reshape_stores
            .get(&shard)
            .map(|s| Arc::clone(&s.storage))
        else {
            warn!(shard = ?shard, "Reshape stage for an unopened store; re-queued");
            let _ = self
                .events_tx
                .send(SupervisorEvent::Reshape(ReshapeIo::StageFailed {
                    shard,
                    progress,
                    leaves,
                }));
            return;
        };
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            match storage.stage_import_chunk(&progress, &leaves) {
                Ok(()) => {
                    let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::Staged { shard }));
                }
                Err(error) => {
                    warn!(shard = ?shard, %error, "Reshape chunk staging failed; re-queued");
                    let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::StageFailed {
                        shard,
                        progress,
                        leaves,
                    }));
                }
            }
        });
    }

    /// Build a reshape duty's boundary state from its staged chunks off
    /// the loop, answering with [`ReshapeIo::Imported`].
    fn reshape_finalize(&self, shard: ShardId, height: BlockHeight) {
        let Some(storage) = self
            .reshape_stores
            .get(&shard)
            .map(|s| Arc::clone(&s.storage))
        else {
            warn!(shard = ?shard, "Reshape finalize for an unopened store; dropped");
            return;
        };
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            match storage.finalize_boundary_import(height, WitnessSeed::default()) {
                Ok(root) => {
                    let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::Imported {
                        shard,
                        root,
                    }));
                }
                Err(error) => warn!(shard = ?shard, %error, "Reshape boundary import failed"),
            }
        });
    }

    /// Apply a followed parent block's writes into a reshape duty's store
    /// off the loop, answering with [`ReshapeIo::Applied`].
    fn reshape_apply(
        &self,
        shard: ShardId,
        block: Arc<Block>,
        creations: Vec<(SubstateKey, Vec<u8>)>,
        frontier: FrontierInputs,
    ) {
        let Some(storage) = self
            .reshape_stores
            .get(&shard)
            .map(|s| Arc::clone(&s.storage))
        else {
            warn!(shard = ?shard, "Reshape follow apply for an unopened store; dropped");
            return;
        };
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            match storage.follow_block_writes(&block, &creations, &frontier) {
                Ok(root) => {
                    let _ =
                        events.send(SupervisorEvent::Reshape(ReshapeIo::Applied { shard, root }));
                }
                Err(error) => warn!(shard = ?shard, %error, "Reshape follow apply failed"),
            }
        });
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
        let Some(signer) = self.vnode_keys.get(&validator) else {
            warn!(
                validator = validator.inner(),
                "Reshape ready signal for a validator without a local key; ignored"
            );
            return;
        };
        let Ok(signal) = observer_ready_signal(
            &self.beacon_network,
            validator,
            child,
            signer.as_ref(),
            anchor,
            self.epoch_duration_ms,
        ) else {
            tracing::error!(
                validator = validator.inner(),
                "cannot sign reshape ready signal; skipping"
            );
            return;
        };
        self.process
            .network()
            .notify(recipients, &ReadySignalNotification::new(signal));
    }

    /// Adopt a reshape duty's derived genesis off the loop via the shared
    /// [`adopt_prepared_store`] gate, answering with [`ReshapeIo::Adopted`];
    /// a gate failure logs and strands the duty (the seat never fires).
    fn reshape_adopt(
        &mut self,
        shard: ShardId,
        kind: AdoptKind,
        origin: ChainOrigin,
        genesis: Block,
        predecessors: Vec<Anchor>,
    ) {
        let Some(storage) = self.reshape_stores.get_mut(&shard).map(|entry| {
            entry.genesis = Some(genesis.clone());
            Arc::clone(&entry.storage)
        }) else {
            warn!(shard = ?shard, "Reshape adopt for an unopened store; dropped");
            return;
        };
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            match adopt_prepared_store(
                storage.as_ref(),
                shard,
                kind,
                origin,
                &genesis,
                predecessors,
            ) {
                Ok(recovered) => {
                    let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::Adopted {
                        shard,
                        recovered,
                    }));
                }
                Err(error) => {
                    warn!(shard = ?shard, error, "Reshape adoption failed; duty stranded");
                }
            }
        });
    }

    /// Seat a prepared reshape duty: install its derived genesis and start
    /// consensus for every local committee member of `shard`, from the
    /// store the duty adopted into. The orchestrator owns this seating, so
    /// the placement-delta join for the same shard is suppressed.
    fn reshape_seat(&mut self, shard: ShardId) {
        let Some(PreparedStore {
            storage,
            recovered,
            genesis,
        }) = self.reshape_stores.remove(&shard)
        else {
            warn!(shard = ?shard, "Reshape seat for an unprepared store; dropped");
            return;
        };
        if self.shards.contains_key(&shard) {
            warn!(shard = ?shard, "Reshape seat for an already-hosted shard; dropped");
            return;
        }
        // The reshape duty owns this successor; an ordinary join racing it
        // yields. Abandon the in-flight join — its opened store drops at
        // `on_opened` (which finds no `bootstrapping` entry) — and seat from the
        // prepared store, which carries the reshape's terminal/merged state the
        // join's snap-sync would not.
        if self.bootstrapping.remove(&shard).is_some() {
            warn!(shard = ?shard, "Reshape seat superseding an in-flight join for the shard");
        }
        let topology_snapshot = self.process.topology_snapshot().load_full();
        let vnodes = self.local_committee_vnodes(&topology_snapshot, shard);
        if vnodes.is_empty() {
            warn!(shard = ?shard, "Reshape seat with no local committee members; dropped");
            return;
        }
        self.seat_shard_with_genesis(shard, &vnodes, storage, &recovered, genesis.as_ref());
    }

    /// Settle one reshape io result: update the duty's [`PreparedStore`]
    /// cache, then translate the result into the orchestrator's
    /// [`ReshapeEvent`] and pump it back through [`Self::reshape_step`].
    pub(super) fn on_reshape_io(&mut self, io: ReshapeIo) {
        let event = match io {
            ReshapeIo::Opened { shard, outcome } => match outcome {
                Ok((storage, recovered)) => {
                    self.reshape_stores.insert(
                        shard,
                        PreparedStore {
                            storage,
                            recovered,
                            genesis: None,
                        },
                    );
                    ReshapeEvent::Opened { shard }
                }
                Err(error) => {
                    warn!(shard = ?shard, error, "Reshape store open failed; duty stranded");
                    return;
                }
            },
            ReshapeIo::Fetched { duty, from, kind } => ReshapeEvent::Fetched { duty, from, kind },
            ReshapeIo::FetchFailed { duty, from, kind } => {
                ReshapeEvent::FetchFailed { duty, from, kind }
            }
            ReshapeIo::Staged { shard } => ReshapeEvent::Staged { shard },
            ReshapeIo::StageFailed {
                shard,
                progress,
                leaves,
            } => ReshapeEvent::StageFailed {
                shard,
                progress,
                leaves,
            },
            ReshapeIo::Imported { shard, root } => ReshapeEvent::Imported { shard, root },
            ReshapeIo::Applied { shard, root } => ReshapeEvent::Applied { shard, root },
            ReshapeIo::Adopted { shard, recovered } => {
                if let Some(entry) = self.reshape_stores.get_mut(&shard) {
                    entry.recovered = recovered;
                }
                ReshapeEvent::Adopted { shard }
            }
            ReshapeIo::SeedDeferred { child } => {
                self.deferred_reshape_events
                    .push(ReshapeEvent::SeedDeferred { child });
                return;
            }
            ReshapeIo::SeedUnavailable { child } => {
                self.reshape_step(vec![ReshapeEvent::SeedUnavailable { child }]);
                self.hand_over_to_join(child);
                return;
            }
        };
        self.reshape_step(vec![event]);
    }

    /// Join `child` through the ordinary membership path once its split duty
    /// relinquished the seat: snap-sync against its attested anchor, or park
    /// until this host's topology carries one. A store the duty prepared is
    /// dropped first, releasing its directory to the join, which wipes what
    /// the duty left there. With no local member placed on the child yet, the
    /// placement delta or the reshape tick's [`Self::reconcile_joins`] joins
    /// it once one is.
    fn hand_over_to_join(&mut self, child: ShardId) {
        if !self.reshape.relinquished(child) {
            return;
        }
        self.reshape_stores.remove(&child);
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

/// A reshape block fetch's result as the io its duty consumes, and the
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
) -> (ReshapeIo, ResponseVerdict) {
    let Ok(response) = result else {
        let kind = FetchKind::Block { request: asked };
        return (
            ReshapeIo::FetchFailed { duty, from, kind },
            ResponseVerdict::Accept,
        );
    };
    let verdict = block_verdict(&asked, &response);
    let kind = FetchedKind::Block {
        response: Box::new(response),
    };
    (ReshapeIo::Fetched { duty, from, kind }, verdict)
}

/// [`block_answer`] for a recognition walk's certified-header fetch.
fn headers_answer(
    duty: ShardId,
    from: ShardId,
    asked: GetRemoteHeadersRequest,
    result: Result<GetRemoteHeadersResponse, RequestError>,
) -> (ReshapeIo, ResponseVerdict) {
    let Ok(response) = result else {
        let kind = FetchKind::Headers { request: asked };
        return (
            ReshapeIo::FetchFailed { duty, from, kind },
            ResponseVerdict::Accept,
        );
    };
    let verdict = headers_verdict(&asked, &response);
    let kind = FetchedKind::Headers {
        response: Box::new(response),
    };
    (ReshapeIo::Fetched { duty, from, kind }, verdict)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_hbor::Capped;
    use hyperscale_network::{RequestError, ResponseVerdict};
    use hyperscale_node::reshape::orchestrator::FetchedKind;
    use hyperscale_storage::test_helpers::make_test_block;
    use hyperscale_types::network::request::{
        BlockIntent, GetBlockRequest, GetRemoteHeadersRequest, MAX_REMOTE_HEADERS_PER_REQUEST,
    };
    use hyperscale_types::network::response::{GetBlockResponse, GetRemoteHeadersResponse};
    use hyperscale_types::test_utils::{TestCommittee, signed_child_block};
    use hyperscale_types::{
        Block, BlockHeight, CertifiedBlockHeader, ElidedCertifiedBlock, Inventory, Round, ShardId,
        ValidatorId, WeightedTimestamp,
    };

    use super::{ReshapeIo, ReshapeSeat, block_answer, headers_answer, host_reshape_owns};

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

        let (io, verdict) = answer(served(&b3));
        assert_eq!(verdict, ResponseVerdict::Reject, "a block off the height");
        assert!(matches!(
            io,
            ReshapeIo::Fetched {
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
        let (io, verdict) = answer(Err(RequestError::Timeout));
        assert_eq!(verdict, ResponseVerdict::Accept);
        assert!(matches!(io, ReshapeIo::FetchFailed { .. }));
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
}
