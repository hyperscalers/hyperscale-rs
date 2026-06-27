//! The simulation harness's reshape adapter.
//!
//! The deterministic counterpart of the production `ShardSupervisor`'s reshape
//! pump: one [`ReshapeOrchestrator`] per host, each driven once per slice from
//! its own committed-state projection. The orchestrator owns the observe /
//! keep / re-assert / follow / adopt / seat sequencing; this adapter performs
//! the io it returns against the in-memory backend and feeds each result back
//! as a [`ReshapeEvent`]. Both harnesses run the *same* orchestrator, so the
//! sequencing can no longer drift between them.
//!
//! io is synchronous here — a fetch serves straight from a committee host's
//! store, an import writes the in-memory tree — so each host's pump drives its
//! orchestrator to a fixpoint per slice rather than waiting on async
//! completions. Progress between slices is gated only by the committed view
//! advancing, which [`SimulationRunner::run_until`] drives.
//!
//! Split parent halves — the splitting committee's own members, which production
//! seats off the placement delta rather than the orchestrator — are flipped
//! here by [`Self::flip_parent_halves`], the simulation's stand-in for that
//! join path. Observers and keepers are the orchestrator's.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::ProtocolEvent;
use hyperscale_engine::GenesisConfig;
use hyperscale_network::Network;
use hyperscale_network_memory::NodeIndex;
use hyperscale_node::bootstrap::replicate_engine_bootstrap;
use hyperscale_node::reshape::adopt::verified_recovered_state;
use hyperscale_node::reshape::observer::observer_ready_signal;
use hyperscale_node::reshape::orchestrator::{
    AdoptKind, FetchKind, FetchedKind, ReshapeEvent, ReshapeRequest,
};
use hyperscale_node::reshape::view::ReshapeView;
use hyperscale_node::shard::HostEvent;
use hyperscale_node::{serve_block_request, serve_state_range_request};
use hyperscale_storage::{BoundaryStore, RecoveredState, ShardChainReader};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::network::notification::ReadySignalNotification;
use hyperscale_types::network::request::GetBlockRequest;
use hyperscale_types::network::response::GetBlockResponse;
use hyperscale_types::{
    Block, BlockHeight, CertifiedBlock, ChainOrigin, ShardId, ValidatorId, Verified,
    shard_prefix_path,
};

use super::SimulationRunner;

/// Drive cap for one host's per-slice reshape fixpoint — generous over the
/// dozens of synchronous rounds a duty's open/sync/follow/adopt/seat chain
/// takes, so exhaustion means a wedge rather than a budget.
const MAX_PUMP_ROUNDS: usize = 100_000;

/// A reshape duty's in-flight store, held between the orchestrator's open and
/// seat for one `(host, duty shard)`. Mirrors the production supervisor's
/// `BootstrappingStore`.
pub(super) struct ReshapeStore {
    /// The opened store the duty imports and adopts into.
    pub(super) storage: SimShardStorage,
    /// The derived genesis, set at adopt, installed at seat.
    pub(super) genesis: Option<Block>,
    /// The recovered state the seated vnodes boot from, rebuilt at adopt.
    pub(super) recovered: RecoveredState,
}

impl SimulationRunner {
    /// Step every host's reshape orchestrator one slice, driving its duties to a
    /// fixpoint against the synchronous in-memory io. Idempotent — safe to call
    /// every slice.
    pub fn pump_reshape(&mut self) {
        for node in 0..self.num_hosts() {
            self.pump_reshape_host(node);
        }
    }

    /// Drive one host's orchestrator to a fixpoint: step it, perform each
    /// request, feed the results back, and repeat until a step produces no io.
    fn pump_reshape_host(&mut self, node: NodeIndex) {
        let Some(topology_snapshot) = self.host_topology(node) else {
            return;
        };
        let view = ReshapeView::new(&topology_snapshot);
        let mut orch = std::mem::take(&mut self.reshape[node as usize]);
        let mut broadcasted: HashSet<ValidatorId> = HashSet::new();
        // Last slice's not-yet-committed block fetches re-arm their sequencers
        // (a `FetchFailed` clears the in-flight flag set when they were issued),
        // so this slice re-requests them — production's fetch callback firing on
        // a later tick.
        let mut events = std::mem::take(&mut self.reshape_pending[node as usize]);
        let mut retries: Vec<ReshapeEvent> = Vec::new();
        for _ in 0..MAX_PUMP_ROUNDS {
            let requests = orch.step(&view, std::mem::take(&mut events));
            let mut progressed = false;
            for request in requests {
                if let Some(event) =
                    self.dispatch_reshape(node, &view, request, &mut broadcasted, &mut retries)
                {
                    events.push(event);
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
        self.reshape_pending[node as usize] = retries;
        self.reshape[node as usize] = orch;
    }

    /// Perform one reshape request, answering with the [`ReshapeEvent`] the
    /// orchestrator consumes (or `None` for the fire-and-forget broadcast and
    /// the terminal seat).
    fn dispatch_reshape(
        &mut self,
        node: NodeIndex,
        view: &ReshapeView,
        request: ReshapeRequest,
        broadcasted: &mut HashSet<ValidatorId>,
        retries: &mut Vec<ReshapeEvent>,
    ) -> Option<ReshapeEvent> {
        match request {
            ReshapeRequest::OpenStore { shard } => {
                self.reshape_open_store(node, shard);
                Some(ReshapeEvent::Opened { shard })
            }
            ReshapeRequest::Fetch { duty, from, kind } => {
                self.reshape_fetch(duty, from, kind, retries)
            }
            ReshapeRequest::SeedFromParent { parent, child } => {
                self.reshape_seed_from_parent(node, parent, child, retries)
            }
            ReshapeRequest::ImportBoundary {
                shard,
                height,
                leaves,
            } => {
                let root = self
                    .reshape_stores
                    .get(&(node, shard))?
                    .storage
                    .import_boundary_state(height, leaves)
                    .expect("reshape boundary import into the opened store");
                Some(ReshapeEvent::Imported { shard, root })
            }
            ReshapeRequest::ApplyFollow {
                shard,
                height,
                receipts,
            } => {
                let root = self
                    .reshape_stores
                    .get(&(node, shard))?
                    .storage
                    .follow_block_writes(height, &receipts)
                    .expect("reshape follow apply into the opened store");
                Some(ReshapeEvent::Applied { shard, root })
            }
            ReshapeRequest::BroadcastReady {
                validator,
                anchor,
                recipients,
            } => {
                // Originate the notify from a recipient's home host — a follower
                // host (a pool observer's dedicated home) shares no shard with
                // the target committee, so the signal must come from within its
                // mesh to reach the receivers that fold the readiness gate. Every
                // recipient is a member of that committee, so its home serves it.
                if broadcasted.insert(validator)
                    && let Some(sender) = self.reshape_notify_origin(&recipients)
                {
                    let signal = observer_ready_signal(
                        &self.beacon_network,
                        validator,
                        &self.signing_keys
                            [usize::try_from(validator.inner()).expect("id fits usize")],
                        anchor,
                        self.epoch_duration_ms,
                    );
                    self.hosts[sender as usize]
                        .network()
                        .notify(&recipients, &ReadySignalNotification::new(signal));
                }
                None
            }
            ReshapeRequest::Adopt {
                shard,
                kind,
                origin,
                genesis,
            } => self.reshape_adopt(node, view, shard, kind, origin, *genesis),
            ReshapeRequest::Seat { shard } => {
                self.reshape_seat(node, view, shard);
                None
            }
        }
    }

    /// Open a fresh duty store, replicate the engine bootstrap into it, and
    /// cache it for the duty.
    fn reshape_open_store(&mut self, node: NodeIndex, shard: ShardId) {
        let storage = SimShardStorage::new(shard_prefix_path(shard));
        replicate_engine_bootstrap(
            &storage,
            &self.beacon_network,
            &GenesisConfig::test_default(),
        );
        let recovered = storage.load_recovered_state();
        self.reshape_stores.insert(
            (node, shard),
            ReshapeStore {
                storage,
                genesis: None,
                recovered,
            },
        );
    }

    /// Seed a parent half's child store by deep-cloning the host's own retained
    /// parent store onto the child subtree, once that parent chain has committed
    /// through the terminal crossing. While it still lags, carry a deferral to
    /// the next slice so the seed re-arms.
    fn reshape_seed_from_parent(
        &mut self,
        node: NodeIndex,
        parent: ShardId,
        child: ShardId,
        retries: &mut Vec<ReshapeEvent>,
    ) -> Option<ReshapeEvent> {
        let ready = self
            .host_topology(node)
            .and_then(|topology_snapshot| topology_snapshot.boundary(child))
            .zip(self.hosts_shard(node, parent))
            .is_some_and(|(anchor, storage)| storage.committed_height() >= anchor.height);
        if !ready {
            retries.push(ReshapeEvent::SeedDeferred { child });
            return None;
        }
        let storage = self.hosts[node as usize]
            .shard_io(parent)
            .storage
            .clone_for_split_child(shard_prefix_path(child));
        let recovered = storage.load_recovered_state();
        self.reshape_stores.insert(
            (node, child),
            ReshapeStore {
                storage,
                genesis: None,
                recovered,
            },
        );
        Some(ReshapeEvent::Opened { shard: child })
    }

    /// Serve one reshape fetch from a committee host's store. A block fetch
    /// returns `None` when no host holds the block yet, so the orchestrator
    /// re-requests on a later slice.
    fn reshape_fetch(
        &self,
        duty: ShardId,
        from: ShardId,
        kind: FetchKind,
        retries: &mut Vec<ReshapeEvent>,
    ) -> Option<ReshapeEvent> {
        match kind {
            FetchKind::StateRange { sub_range, request } => {
                // Serve from any host that has pinned the boundary version — a
                // terminated half's hosts can lag each other onto its terminal.
                // If none can yet, carry a failure to the next slice (re-arming
                // the sub-range) rather than feeding an empty chunk that would
                // spin the fixpoint.
                let response = (0..self.num_hosts())
                    .filter(|&node| self.hosts_shard(node, from).is_some())
                    .map(|node| {
                        serve_state_range_request(
                            &self.hosts[node as usize].shard_io(from).storage,
                            &request,
                        )
                    })
                    .find(|r| r.chunk.is_some());
                let Some(response) = response else {
                    retries.push(ReshapeEvent::FetchFailed {
                        duty,
                        from,
                        kind: FetchKind::StateRange { sub_range, request },
                    });
                    return None;
                };
                Some(ReshapeEvent::Fetched {
                    duty,
                    from,
                    kind: FetchedKind::StateRange {
                        sub_range,
                        response: Box::new(response),
                    },
                })
            }
            FetchKind::Block { request } => {
                let response = self.serve_reshape_block(from, &request);
                if response.certified.is_none() {
                    // The block has not committed yet: carry a failure to the
                    // next slice, which re-arms the sequencer and re-requests.
                    // The fetch stays in flight until then, so the fixpoint
                    // makes no progress on it this slice.
                    retries.push(ReshapeEvent::FetchFailed {
                        duty,
                        from,
                        kind: FetchKind::Block { request },
                    });
                    return None;
                }
                Some(ReshapeEvent::Fetched {
                    duty,
                    from,
                    kind: FetchedKind::Block {
                        response: Box::new(response),
                    },
                })
            }
        }
    }

    /// The host to originate a ready-signal notify from: the home host of the
    /// first recipient. Each recipient is a member of the target committee, so
    /// its home serves the target shard and sits in the mesh the receivers
    /// fold the gate on. `None` only if no recipient has a home.
    fn reshape_notify_origin(&self, recipients: &[ValidatorId]) -> Option<NodeIndex> {
        recipients.iter().find_map(|recipient| {
            self.validator_home
                .get(usize::try_from(recipient.inner()).expect("id fits usize"))
                .copied()
        })
    }

    /// Serve a block for a reshape duty. A keeper's terminal sits in the
    /// merging child's own chain (`from`); an observer follows the splitting
    /// parent's chain even after the child anchor projects, so a child-targeted
    /// request falls back to the parent's retained chain.
    fn serve_reshape_block(&self, from: ShardId, request: &GetBlockRequest) -> GetBlockResponse {
        let mut sources = vec![from];
        if let Some(parent) = from.parent() {
            sources.push(parent);
        }
        for shard in sources {
            for node in 0..self.num_hosts() {
                if self.hosts_shard(node, shard).is_none() {
                    continue;
                }
                let io = self.hosts[node as usize].shard_io(shard);
                let response =
                    serve_block_request(&io.pending_chain, &io.caches.provision_store, request);
                if response.certified.is_some() {
                    return response;
                }
            }
        }
        GetBlockResponse::not_found()
    }

    /// Adopt a duty's derived genesis into its store, verifying the adopted
    /// root against the beacon anchor, and cache the genesis plus the recovered
    /// state the seat boots from.
    fn reshape_adopt(
        &mut self,
        node: NodeIndex,
        view: &ReshapeView,
        shard: ShardId,
        kind: AdoptKind,
        origin: ChainOrigin,
        genesis: Block,
    ) -> Option<ReshapeEvent> {
        let storage = self.reshape_stores.get(&(node, shard))?.storage.clone();
        let (adopted, expected) = match kind {
            AdoptKind::Split => (
                storage
                    .adopt_followed_child(origin, &genesis)
                    .expect("followed child adoption"),
                genesis.header().state_root(),
            ),
            AdoptKind::ParentHalf => (
                storage
                    .adopt_split_child(origin, &genesis)
                    .expect("split child subtree adoption"),
                view.boundary(shard)
                    .expect("split child anchor projects")
                    .state_root,
            ),
            AdoptKind::Merge => (
                storage
                    .adopt_merge_parent(origin, &genesis)
                    .expect("merge parent adoption"),
                view.boundary(shard)
                    .expect("merge parent anchor projects")
                    .state_root,
            ),
        };
        let substate_bytes = storage
            .substate_bytes_at_version(origin.genesis_height.inner())
            .unwrap_or(0);
        let recovered = verified_recovered_state(adopted, expected, origin, substate_bytes)
            .expect("adopted reshape root must match the beacon anchor");
        let entry = self.reshape_stores.get_mut(&(node, shard))?;
        entry.genesis = Some(genesis);
        entry.recovered = recovered;
        Some(ReshapeEvent::Adopted { shard })
    }

    /// Seat a prepared duty: install its genesis and start consensus for every
    /// committee member of `shard` this host homes, from the duty's adopted
    /// store.
    fn reshape_seat(&mut self, node: NodeIndex, view: &ReshapeView, shard: ShardId) {
        let Some(ReshapeStore {
            storage,
            genesis,
            recovered,
        }) = self.reshape_stores.remove(&(node, shard))
        else {
            return;
        };
        let genesis = genesis.expect("reshape seat follows the adopt");
        let validators: Vec<ValidatorId> = view
            .committee(shard)
            .iter()
            .copied()
            .filter(|validator| self.homes_validator(node, *validator))
            .collect();
        if validators.is_empty() {
            return;
        }
        self.seat_reshape_shard(node, shard, &validators, storage, &genesis, &recovered);
    }

    /// Install a prepared store on `node`: seat one vnode per `validator`,
    /// commit the genesis through the normal pipeline, and retire any pool
    /// follower the seated validator carried. Tears down a stale chain under
    /// the same id first — a merge reforms the grow's terminated parent.
    fn seat_reshape_shard(
        &mut self,
        node: NodeIndex,
        shard: ShardId,
        validators: &[ValidatorId],
        storage: SimShardStorage,
        genesis: &Block,
        recovered: &RecoveredState,
    ) {
        let _ = self.hosts[node as usize].remove_shard(shard);
        let mut inits = Vec::with_capacity(validators.len());
        for &validator in validators {
            inits.push(self.runtime_vnode_init(node, validator, shard, recovered));
            self.network.bind_validator(validator, node);
        }
        self.hosts[node as usize].add_shard(inits, storage, self.event_txs[node as usize].clone());
        self.hosts[node as usize].initialize_shard_genesis(genesis);
        self.hosts[node as usize].flush_all_batches();
        let output = self.hosts[node as usize].drain_pending_output();
        self.drain_node_io(node);
        self.process_step_output(node, output);
        let certified = Arc::new(Verified::<CertifiedBlock>::genesis_certified(
            genesis.clone(),
        ));
        self.schedule_event(
            node,
            self.now,
            HostEvent::protocol(shard, ProtocolEvent::BlockCommitted { certified }),
        );
        for &validator in validators {
            self.hosts[node as usize].drop_pooled_vnode(validator);
        }
    }

    /// Whether `validator`'s fixed home host is `node`.
    fn homes_validator(&self, node: NodeIndex, validator: ValidatorId) -> bool {
        self.validator_home
            .get(usize::try_from(validator.inner()).expect("id fits usize"))
            .copied()
            == Some(node)
    }

    /// Grow the current single-shard topology until it holds `target_shards`
    /// leaves, each committing past its child genesis, by driving the real
    /// split lifecycle through the per-host orchestrators.
    ///
    /// The caller must have run genesis first
    /// (`initialize_genesis` / `initialize_genesis_with_balances`) and armed
    /// the split trigger (`ReshapeThresholds { split_bytes: 0 }`) with one
    /// cohort of pooled extras per split — `(target_shards - 1) * shard_size`
    /// in total. A thin wrapper over [`Self::pump_reshape`]: each slice pumps
    /// every host's orchestrator and advances the clock, until the leaves
    /// reshape into the target partition and commit.
    ///
    /// # Panics
    ///
    /// Panics if `target_shards` is not a power of two, or if the grow does not
    /// reach the target partition within its epoch budget.
    pub fn grow_to(&mut self, target_shards: u32) {
        assert!(
            target_shards.is_power_of_two(),
            "grow_to target must be a power of two; got {target_shards}",
        );
        let target = u64::from(target_shards);
        // One generation per level of depth; budget each generously over the
        // admission → gate → seed → child-run phases its splits walk through.
        let depth = u64::from(target_shards.trailing_zeros());
        let budget_epochs = depth.saturating_mul(60).max(60);
        let deadline = self.now + Duration::from_millis(self.epoch_duration_ms * budget_epochs);
        loop {
            if self.grown_to(target) {
                return;
            }
            assert!(
                self.now < deadline,
                "grow_to did not reach {target_shards} shards within {budget_epochs} epochs",
            );
            self.pump_reshape();
            let next = self.now + Duration::from_secs(1);
            self.run_until(next);
        }
    }

    /// Whether the topology holds at least `target` leaves and each is fully
    /// formed: every committee member seated and committing past its child
    /// genesis. Waiting for the whole committee — not just a quorum on some
    /// host — keeps a post-grow workload from racing a straggler that seats
    /// after the transaction lands and so never carries it to a terminal
    /// outcome; the pump only advances duties while `grow_to` drives it, so a
    /// member left unseated at return never catches up.
    fn grown_to(&self, target: u64) -> bool {
        let Some(topology_snapshot) = self.host_topology(0) else {
            return false;
        };
        let leaves: Vec<ShardId> = topology_snapshot.shard_trie().leaves().collect();
        leaves.len() as u64 >= target
            && leaves.iter().all(|&leaf| {
                let past_genesis = (0..self.num_hosts()).any(|node| {
                    self.hosts_shard(node, leaf)
                        .is_some_and(|storage| storage.committed_height() > BlockHeight::GENESIS)
                });
                let seated: Vec<ValidatorId> = self
                    .shard_vnodes(leaf)
                    .iter()
                    .map(|vnode| vnode.validator_id())
                    .collect();
                let committee = topology_snapshot.committee_for_shard(leaf);
                past_genesis
                    && !committee.is_empty()
                    && committee.iter().all(|member| seated.contains(member))
            })
    }
}
