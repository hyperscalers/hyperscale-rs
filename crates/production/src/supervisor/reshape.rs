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

use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_network_libp2p::Libp2pNetwork;
use hyperscale_node::reshape::PreparedStore;
use hyperscale_node::reshape::adopt::adopt_prepared_store;
use hyperscale_node::reshape::observer::observer_ready_signal;
use hyperscale_node::reshape::orchestrator::{
    AdoptKind, FetchKind, FetchedKind, ReshapeEvent, ReshapeRequest,
};
use hyperscale_node::reshape::view::ReshapeView;
use hyperscale_node::serve_state_range_request;
use hyperscale_storage::{BoundaryStore, ImportLeaf, RecoveredState, ShardChainReader};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::network::notification::ReadySignalNotification;
use hyperscale_types::network::request::GetStateRangeRequest;
use hyperscale_types::{
    Block, BlockHeight, ChainOrigin, ShardAnchor, ShardId, StateRoot, StoredReceipt, ValidatorId,
};
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::{ShardSupervisor, SupervisorEvent};

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
    /// the terminal crossing — so the seed should be re-armed.
    SeedDeferred {
        /// The split child whose seed is deferred.
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
    /// otherwise race the reshape duty for the shard's store directory.
    pub(super) fn reshape_owns(&self, shard: ShardId) -> bool {
        let topology_snapshot = self.process.topology_snapshot().load_full();
        let view = ReshapeView::new(&topology_snapshot);
        host_reshape_owns(
            view.parent_half_cohorts(),
            view.observer_cohorts(),
            view.keeper_cohorts(),
            shard,
            |validator| self.vnode_keys.contains_key(validator),
        )
    }

    /// Pump the reshape orchestrator one step: feed back the io results in
    /// `events`, let it re-discover this host's duties from the committed
    /// topology projection, and perform the io it returns. Idempotent; the
    /// runner ticks it on a timer and on every placement change.
    pub(crate) fn reshape_step(&mut self, events: Vec<ReshapeEvent>) {
        self.resume_pending_reshape_prep();
        let requests = {
            let topology_snapshot = self.process.topology_snapshot().load_full();
            let view = ReshapeView::new(&topology_snapshot);
            self.reshape.step(&view, events)
        };
        for request in requests {
            self.dispatch_reshape(request);
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
        match request {
            ReshapeRequest::OpenStore { shard } => self.reshape_open_store(shard),
            ReshapeRequest::SeedFromParent { parent, child } => {
                self.reshape_seed_from_parent(parent, child);
            }
            ReshapeRequest::Fetch { duty, from, kind } => self.reshape_fetch(duty, from, kind),
            ReshapeRequest::ImportBoundary {
                shard,
                height,
                leaves,
            } => self.reshape_import(shard, height, leaves),
            ReshapeRequest::ApplyFollow {
                shard,
                height,
                receipts,
            } => self.reshape_apply(shard, height, receipts),
            ReshapeRequest::BroadcastReady {
                validator,
                anchor,
                recipients,
            } => self.reshape_broadcast(validator, anchor, &recipients),
            ReshapeRequest::Adopt {
                shard,
                kind,
                origin,
                genesis,
            } => self.reshape_adopt(shard, kind, origin, *genesis),
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
                let storage = factory(shard)?;
                // The directory was just wiped, so the store is fresh: it must
                // carry the engine bootstrap on its substate side before the
                // duty's child-span or merged-union import, or the seated shard
                // would lack the global engine nodes (the transaction tracker,
                // the consensus manager) every transaction reads.
                engine_bootstrap.replicate_into(storage.as_ref());
                let recovered = storage.load_recovered_state();
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
    /// [`ReshapeIo::Opened`] when the clone lands, or [`ReshapeIo::SeedDeferred`]
    /// while the local parent is still behind (or its store is gone). The
    /// checkpoint hard-links, so the clone shares the engine bootstrap and the
    /// parent's substates without copying.
    fn reshape_seed_from_parent(&self, parent: ShardId, child: ShardId) {
        let events = self.events_tx.clone();
        let Some(anchor) = self.process.topology_snapshot().load().boundary(child) else {
            let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::SeedDeferred { child }));
            return;
        };
        let parent_storage = self
            .storages
            .lock()
            .expect("storages lock")
            .get(&parent)
            .cloned();
        let Some(parent_storage) = parent_storage else {
            warn!(shard = ?child, ?parent, "Reshape seed without a hosted parent store; deferred");
            let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::SeedDeferred { child }));
            return;
        };
        let factory = Arc::clone(&self.storage_factory);
        let dir = (self.storage_dir)(child);
        self.tokio_handle.spawn_blocking(move || {
            // The anchor's height is the child genesis height; the parent commits
            // one block past its terminal (the coast certifying it), so the local
            // chain is ready for the clone once its tip reaches the anchor.
            if parent_storage.committed_height() < anchor.height {
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
                let storage = factory(child)?;
                let recovered = storage.load_recovered_state();
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
            FetchKind::Block { request } => {
                let on_fail = request.clone();
                self.process.network().request(
                    from,
                    None,
                    request,
                    None,
                    Box::new(move |result| {
                        let io = result.map_or_else(
                            |_| ReshapeIo::FetchFailed {
                                duty,
                                from,
                                kind: FetchKind::Block { request: on_fail },
                            },
                            |response| ReshapeIo::Fetched {
                                duty,
                                from,
                                kind: FetchedKind::Block {
                                    response: Box::new(response),
                                },
                            },
                        );
                        let _ = events.send(SupervisorEvent::Reshape(io));
                        ResponseVerdict::Accept
                    }),
                );
            }
        }
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

    /// Write a reshape duty's boundary leaves into its store off the loop,
    /// answering with [`ReshapeIo::Imported`].
    fn reshape_import(&self, shard: ShardId, height: BlockHeight, leaves: Vec<ImportLeaf>) {
        let Some(storage) = self
            .reshape_stores
            .get(&shard)
            .map(|s| Arc::clone(&s.storage))
        else {
            warn!(shard = ?shard, "Reshape import for an unopened store; dropped");
            return;
        };
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            match storage.import_boundary_state(height, leaves) {
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
    fn reshape_apply(&self, shard: ShardId, height: BlockHeight, receipts: Vec<StoredReceipt>) {
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
            match storage.follow_block_writes(height, &receipts) {
                Ok(root) => {
                    let _ =
                        events.send(SupervisorEvent::Reshape(ReshapeIo::Applied { shard, root }));
                }
                Err(error) => warn!(shard = ?shard, %error, "Reshape follow apply failed"),
            }
        });
    }

    /// Sign `validator`'s ready signal anchored at `anchor` and notify the
    /// reshape committee `recipients`. No response — the orchestrator
    /// re-asserts each step until the gate fires.
    fn reshape_broadcast(
        &self,
        validator: ValidatorId,
        anchor: ShardAnchor,
        recipients: &[ValidatorId],
    ) {
        let Some(signing_key) = self.vnode_keys.get(&validator) else {
            warn!(
                validator = validator.inner(),
                "Reshape ready signal for a validator without a local key; ignored"
            );
            return;
        };
        let signal = observer_ready_signal(
            &self.beacon_network,
            validator,
            signing_key,
            anchor,
            self.epoch_duration_ms,
        );
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
    ) {
        let Some(storage) = self.reshape_stores.get_mut(&shard).map(|entry| {
            entry.genesis = Some(genesis.clone());
            Arc::clone(&entry.storage)
        }) else {
            warn!(shard = ?shard, "Reshape adopt for an unopened store; dropped");
            return;
        };
        let anchor_root = self
            .process
            .topology_snapshot()
            .load()
            .boundary(shard)
            .map(|a| a.state_root);
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            match adopt_prepared_store(storage.as_ref(), kind, origin, &genesis, anchor_root) {
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
            ReshapeIo::Imported { shard, root } => ReshapeEvent::Imported { shard, root },
            ReshapeIo::Applied { shard, root } => ReshapeEvent::Applied { shard, root },
            ReshapeIo::Adopted { shard, recovered } => {
                if let Some(entry) = self.reshape_stores.get_mut(&shard) {
                    entry.recovered = recovered;
                }
                ReshapeEvent::Adopted { shard }
            }
            ReshapeIo::SeedDeferred { child } => ReshapeEvent::SeedDeferred { child },
        };
        self.reshape_step(vec![event]);
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
    observer_cohorts: &BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    keeper_cohorts: &BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    shard: ShardId,
    owned: impl Fn(&ValidatorId) -> bool,
) -> bool {
    if parent_half_cohorts
        .get(&shard)
        .is_some_and(|seats| seats.keys().any(&owned))
    {
        return true;
    }
    if observer_cohorts
        .values()
        .any(|seats| seats.iter().any(|(v, child)| *child == shard && owned(v)))
    {
        return true;
    }
    keeper_cohorts
        .values()
        .any(|seats| seats.iter().any(|(v, parent)| *parent == shard && owned(v)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{ShardId, ValidatorId};

    use super::host_reshape_owns;

    const HOST: ValidatorId = ValidatorId::new(1);

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
        let observers = BTreeMap::from([(parent, BTreeMap::from([(HOST, child)]))]);
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
        let keepers = BTreeMap::from([(child, BTreeMap::from([(HOST, parent)]))]);
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
