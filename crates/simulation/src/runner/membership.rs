//! The harness's membership half: bring shards up and tear them down
//! against the committed beacon placement.
//!
//! Hosted replicas surface [`ParticipationChange`]s through `StepOutput`;
//! the committed projection drives the actual joins and leaves — a join
//! runs the same sans-io [`ShardBootstrap`] sequencer production drives
//! (state assembly with per-chunk staging → finalize + anchor
//! verification → witness history → recovered state), served straight from the target committee's hosts'
//! storages, then runs the shard via `NodeHost::add_shard` with the
//! validator attached; a leave tears the shard down via
//! `NodeHost::remove_shard`, handing back a shared storage handle so a
//! later rejoin exercises the retained-storage fast path. A validator
//! drawn onto a shard its host already runs attaches to the running
//! replica (`NodeHost::attach_signer`), and one that loses its role there
//! detaches from it (`NodeHost::detach_signer`) while the loop stays up.
//!
//! The join half reads the seatable committee view (split-observer riders
//! excluded); the teardown half reads full membership — the same
//! asymmetry as the production supervisor's reconcile pair.
//!
//! Reshape duties and placement are two seaters over one set of shards, so
//! a driver that polls only one leaves the other's work undone. Drive both
//! through [`SimulationRunner::topology_step`] rather than calling them
//! separately.

use std::collections::HashSet;
use std::sync::Arc;

use hyperscale_core::ParticipationChange;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_memory::NodeIndex;
use hyperscale_node::bootstrap::{
    BootstrapRequest, BootstrapResponse, ShardBootstrap, StoreResponder, replicate_engine_bootstrap,
};
use hyperscale_node::startup::{
    HostedView, Replaced, SeatChange, join_wipe, reconcile, record_fork_anchor, reseat,
};
use hyperscale_node::{HostedChain, ReplicaConfig};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BoundaryStore, RecoveredState, carry_signed_rounds, history_floor};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{BlockHeight, ShardAnchor, ShardId, Signer, ValidatorId};

use super::{SimulationRunner, open_store};

/// Drive cap for the snap-sync pump — generous over the dozens of
/// rounds a small-state bootstrap takes, so exhaustion means a wedge.
pub(super) const MAX_BOOTSTRAP_ROUNDS: usize = 100_000;

/// Which join path [`SimulationRunner::join_shard`] took. Mirrors the
/// production supervisor's branching on the store's recovered state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinKind {
    /// Fresh store, bootstrapped via snap-sync against the attested
    /// anchor; tail block sync continues from `anchor_height + 1`.
    SnapSync {
        /// The beacon-attested boundary the import verified against.
        anchor_height: BlockHeight,
    },
    /// Retained store resumed in place — no snap-sync; tail block sync
    /// continues from the retained tip.
    Retained {
        /// The retained store's committed tip at rejoin.
        committed_height: BlockHeight,
    },
    /// Fresh store on a shard born at network genesis that has not yet
    /// crossed a boundary: the store installs the network genesis and the
    /// chain replays from it through block sync.
    Genesis,
    /// Fresh store, but this host's topology carries neither the shard's
    /// attested anchor nor a genesis to replay: nothing was seated, and
    /// the placement scan retries next slice once the fold reaches the
    /// host.
    AwaitingAnchor,
}

/// The answer `request` gets from `peers`, asked from `start` on. A
/// history request goes round them as the transport does: a peer without
/// the block passes it on, and it ends empty only once every peer has,
/// with the last empty answer. Any other request asks one peer.
fn ask_peers(
    peers: &[StoreResponder<SimShardStorage>],
    start: usize,
    request: &BootstrapRequest,
) -> Option<BootstrapResponse> {
    if !matches!(request, BootstrapRequest::History(..)) {
        return peers[start % peers.len()].peer_answer(request);
    }
    let mut last = None;
    for k in 0..peers.len() {
        last = peers[(start + k) % peers.len()].peer_answer(request);
        if let Some(BootstrapResponse::History(_, block)) = &last
            && block.has_block()
        {
            break;
        }
    }
    last
}

impl SimulationRunner {
    /// Drain the placement deltas the hosts emitted since the last
    /// call, in deterministic event order.
    pub fn take_participation_changes(&mut self) -> Vec<(NodeIndex, ParticipationChange)> {
        std::mem::take(&mut self.pending_participation_changes)
    }

    /// Begin hosting `shard` for `validator` on `host` at runtime,
    /// bootstrapping `storage` exactly the way the production
    /// supervisor would: a retained store (committed past genesis)
    /// seats directly, a fresh store snap-syncs against the
    /// beacon-attested anchor through the [`ShardBootstrap`] sequencer,
    /// served from the shard's current committee hosts, or replays from
    /// the network genesis on a genesis-born shard that has not crossed a
    /// boundary.
    ///
    /// # Panics
    ///
    /// Panics if the shard has no serving host (the simulation models no
    /// fully dark committee), or if the imported root diverges from the
    /// anchor.
    pub fn join_shard(
        &mut self,
        host: NodeIndex,
        validator: ValidatorId,
        shard: ShardId,
        storage: SimShardStorage,
    ) -> JoinKind {
        self.seat_joined_group(host, shard, &[validator], storage)
    }

    /// Seat a group of this host's committee members onto `shard` from one
    /// `storage`: a retained store (committed past genesis) resumes in place, a
    /// fresh store snap-syncs against the beacon-attested anchor through the
    /// [`ShardBootstrap`] sequencer, served from the shard's current committee,
    /// and a fresh store on a genesis-born shard with no crossing yet installs
    /// the network genesis and replays the chain from it.
    ///
    /// The routing question is whether there is a chain to resume, so it reads
    /// the committed tip. That is not the question the import gate asks —
    /// `hyperscale_storage::holds_state` reads the trie, and the two answer
    /// differently for a store whose trie an adoption filled while its
    /// coordinator sits at genesis. A seat that read the trie would resume a
    /// chain holding no blocks.
    ///
    /// Every member shares the one store and one bootstrap, mirroring the
    /// production supervisor seating a whole committee group at once. A snap-sync
    /// whose attested anchor has gone stale leaves the group unseated; the
    /// placement scan retries it next slice.
    ///
    /// # Panics
    ///
    /// Panics if a fresh store has no serving host, or if the imported root
    /// diverges from the anchor.
    fn seat_joined_group(
        &mut self,
        host: NodeIndex,
        shard: ShardId,
        validators: &[ValidatorId],
        storage: SimShardStorage,
    ) -> JoinKind {
        let recovered = storage.load_recovered_state(shard);
        let (recovered, kind) = if recovered.committed_height > BlockHeight::GENESIS {
            let committed_height = recovered.committed_height;
            (recovered, JoinKind::Retained { committed_height })
        } else {
            let snapshot = self.hosts[host as usize]
                .process()
                .topology_snapshot()
                .load_full();
            let Some(anchor) = snapshot.boundary(shard) else {
                if snapshot.genesis_unanchored(shard) {
                    self.seat_group_at_genesis(host, shard, validators, storage);
                    return JoinKind::Genesis;
                }
                return JoinKind::AwaitingAnchor;
            };
            // A fresh store needs the engine bootstrap (system packages, the
            // intent-hash tracker) before the snap-sync import, exactly as the
            // reshape duty and the production supervisor seed a fresh store —
            // the authenticated span import overwrites only the prefix subtree.
            replicate_engine_bootstrap(&storage, &self.genesis_config());
            let Some(recovered) =
                self.bootstrap_from_committee(host, shard, anchor, &storage, false)
            else {
                // The attested anchor has aged out of what the serving
                // committee retains — a transient fold freeze, or this
                // host's beacon trailing the committee's. Defer the seat;
                // the placement scan retries next slice against the
                // advanced anchor.
                return JoinKind::SnapSync {
                    anchor_height: anchor.height,
                };
            };
            (
                recovered,
                JoinKind::SnapSync {
                    anchor_height: anchor.height,
                },
            )
        };
        self.seat_group(host, shard, validators, storage, &recovered);
        kind
    }

    /// Mount `shard` on `host` over a fresh `storage` at the network genesis,
    /// seating `validators` on it: the same ceremony the cluster ran at birth,
    /// so the block every other store committed at genesis is the one this
    /// store commits, and block sync carries the chain forward from there.
    fn seat_group_at_genesis(
        &mut self,
        host: NodeIndex,
        shard: ShardId,
        validators: &[ValidatorId],
        storage: SimShardStorage,
    ) {
        let recovered = storage.load_recovered_state(shard);
        for &validator in validators {
            self.network.bind_validator(validator, host);
        }
        self.add_shard(host, shard, validators, storage, &recovered);
        self.install_shard_genesis(host, shard, &self.genesis_config());
    }

    /// Mount `shard` on `host` over `storage`, seating `validators` from the
    /// state it recovered to.
    fn seat_group(
        &mut self,
        host: NodeIndex,
        shard: ShardId,
        validators: &[ValidatorId],
        storage: SimShardStorage,
        recovered: &RecoveredState,
    ) {
        // Bind each seated validator to this host in the transport's layout,
        // as the reshape seat does, so every notification addressed to it —
        // headers, votes, ready-signal traffic — reaches the seat.
        for &validator in validators {
            self.network.bind_validator(validator, host);
        }
        self.add_shard(host, shard, validators, storage, recovered);
        // Resume consensus from the recovered committed state, as the
        // production supervisor does pre-spawn: this arms the pacemaker and
        // cleanup timers, so a committee seated onto a quiet chain (a halt
        // recovery's fresh committee) still enters consensus.
        let output = self.hosts[host as usize].resume_shard_committed(shard, recovered);
        self.process_step_output(host, output);
        self.drain_host_io(host);
    }

    /// Advance both seaters over the committed topology: reshape duties
    /// first so they claim `is_seating`, then ordinary committee placement.
    ///
    /// A driver that polls only [`Self::reshape_step`] grows and merges
    /// correctly but never staffs a seat the shuffle rotates, so the beacon
    /// moves a validator that nothing follows and the shard it left runs a
    /// member short. Both are idempotent and self-gated — reshape on its
    /// orchestrators, placement on the host's committed epoch — so a driver
    /// calls this as often as it likes.
    pub fn topology_step(&mut self) {
        self.reshape_step();
        self.reconcile_placement();
        self.reseat_step();
    }

    /// Re-seat every shard a loop asked to: its store needs a height
    /// beneath every serving peer's chain floor, so block sync cannot carry
    /// it forward. The counterpart of the production supervisor's
    /// `reseat`: the loop is rebuilt at the shard's attested anchor as
    /// [`reseat`] plans. A shard no longer hosted, one a reshape duty is
    /// seating, and one with no attested anchor have nothing to re-seat; a
    /// rebuild that cannot complete yet asks again on the loop's next
    /// below-floor answer.
    fn reseat_step(&mut self) {
        for (host, shard) in std::mem::take(&mut self.pending_reseats) {
            if !self.hosted_shards_of(host).contains(&shard)
                || self.reshape[host as usize].is_seating(shard)
            {
                continue;
            }
            let schedule = self.hosts[host as usize].process().topology_schedule();
            let carried = self.hosts[host as usize].signers(shard);
            let local: HashSet<ValidatorId> = self.homed_validators(host).into_iter().collect();
            let head = self.hosts[host as usize]
                .process()
                .topology_snapshot()
                .load_full();
            if let Some(change) = reseat(shard, &schedule, &head, &carried, &local) {
                self.apply_seat_change(host, change);
            }
        }
    }

    /// Reconcile each host's physical shard membership against the
    /// committed beacon placement, carrying out the seat changes
    /// [`reconcile`] plans: the plan the production supervisor carries out
    /// too. A leaf a reshape duty owns (`is_seating`) is left to the
    /// orchestrator to seat. Idempotent; safe to call every slice.
    ///
    /// The placement deltas the hosts emit are drained, since the committed
    /// projection drives the actual join/leave: the snap-sync usually
    /// completes within the slice, and a join whose attested anchor has
    /// gone stale (a transient fold freeze evicted its state) simply defers
    /// to a later slice, the same way production's async bootstrap retries
    /// against the advanced anchor.
    pub(crate) fn reconcile_placement(&mut self) {
        let _ = self.take_participation_changes();
        for host in 0..self.num_hosts() {
            // Committee membership only changes at an epoch boundary, so skip the
            // reconciliation scan until this host's committed epoch advances.
            let Some(epoch) = self
                .beacon_storage(host)
                .and_then(|storage| storage.latest_committed_epoch())
            else {
                continue;
            };
            if self.placement_epoch[host as usize] == Some(epoch) {
                continue;
            }
            self.placement_epoch[host as usize] = Some(epoch);

            let process = self.hosts[host as usize].process();
            let schedule = process.topology_schedule();
            let head = process.topology_snapshot().load_full();
            let routing = process.network().routing_committees();
            let local: HashSet<ValidatorId> = self.homed_validators(host).into_iter().collect();
            let node = &self.hosts[host as usize];
            let orchestrator = &self.reshape[host as usize];
            let hosted: Vec<HostedView<'_, SimShardStorage>> = node
                .hosted_shards()
                .map(|shard| HostedView {
                    shard,
                    store: Some(&**node.shard_io(shard).storage()),
                    attached: node.signers(shard),
                    attaching: Vec::new(),
                    seatable: !orchestrator.is_seating(shard),
                })
                .collect();
            let changes = reconcile(&schedule, &head, &routing, &hosted, &local, |shard| {
                !orchestrator.is_seating(shard)
            });
            for change in changes {
                self.apply_seat_change(host, change);
            }
        }
    }

    /// Carry out one planned seat change on `host`.
    fn apply_seat_change(&mut self, host: NodeIndex, change: SeatChange) {
        match change {
            SeatChange::Retire(shard) => {
                let storage = self.leave_shard(host, shard);
                self.retained_storages.insert((host, shard), storage);
            }
            SeatChange::Detach(shard, validator) => {
                self.hosts[host as usize].detach_signer(shard, validator);
            }
            SeatChange::Rebuild {
                shard,
                seats,
                replaced,
            } => self.rebuild_shard(host, shard, &seats, replaced),
            SeatChange::Attach(shard, validator) => {
                self.attach_to_running_loop(host, shard, validator);
            }
            SeatChange::Join(shard, validators) => {
                let schedule = self.hosts[host as usize].process().topology_schedule();
                let storage = self
                    .retained_storages
                    .remove(&(host, shard))
                    // The seat has two branches and between them they take a
                    // store with a chain or a store with nothing, so a retained
                    // store resumes only once it committed past genesis. A
                    // store that snap-synced and left before committing holds
                    // the import's state under no chain: it is an abandoned
                    // bootstrap, and the seat starts again from an empty store
                    // against the anchor that has since advanced. Nor does a
                    // store a join wipes ([`join_wipe`]) resume.
                    .filter(|storage| {
                        storage.load_recovered_state(shard).committed_height > BlockHeight::GENESIS
                            && join_wipe(storage, shard, &schedule).is_none()
                    })
                    .unwrap_or_else(|| open_store(shard, self.power_loss));
                self.seat_joined_group(host, shard, &validators, storage);
                // A join that deferred — no anchor yet, or one whose state
                // has aged out — seats nothing; the scan runs again next
                // slice rather than at the next committed epoch.
                if !self.hosted_shards_of(host).contains(&shard) {
                    self.placement_epoch[host as usize] = None;
                }
            }
        }
    }

    /// Attach `validator` to `host`'s running replica of `shard`, binding
    /// it into the transport's layout first so traffic addressed to it
    /// lands from the moment it is attached.
    fn attach_to_running_loop(&mut self, host: NodeIndex, shard: ShardId, validator: ValidatorId) {
        self.network.bind_validator(validator, host);
        let signer = self.signer_of(validator);
        let output = self.hosts[host as usize].attach_signer(shard, validator, signer);
        self.process_step_output(host, output);
        self.drain_host_io(host);
    }

    /// Rebuild `host`'s loop for `shard` at the beacon-attested anchor and
    /// seat `placed` on it.
    ///
    /// Make before break: a staging store snap-syncs while the old loop keeps
    /// running, reading the old store first and peers for what it no longer
    /// holds, so hosts rebuilding at once still source each other. Only then
    /// does the old loop come down with its store, and a store that fell
    /// behind hands the rounds signed on it to the staging store; a
    /// validator the old loop carried that is not placed here keeps its
    /// beacon participant. A staging
    /// store that cannot complete is dropped and the rebuild retries next
    /// slice, as a join does.
    fn rebuild_shard(
        &mut self,
        host: NodeIndex,
        shard: ShardId,
        placed: &[ValidatorId],
        replaced: Replaced,
    ) {
        let anchor = self.hosts[host as usize]
            .process()
            .topology_snapshot()
            .load()
            .boundary(shard)
            .expect("a recovering shard has an attested anchor");
        let staging = open_store(shard, self.power_loss);
        replicate_engine_bootstrap(&staging, &self.genesis_config());
        let Some(recovered) = self.bootstrap_from_committee(host, shard, anchor, &staging, true)
        else {
            return;
        };
        // The old loop is down, so its store holds every round it signed in.
        let old = self.leave_shard(host, shard);
        if replaced == Replaced::Behind {
            carry_signed_rounds(&old, &staging);
        }
        drop(old);
        self.retained_storages.remove(&(host, shard));
        self.seat_group(host, shard, placed, staging, &recovered);
    }

    /// Run `validator` on `host` from here on, as an operator moving a
    /// validator between machines while it holds no seat: its beacon
    /// participant leaves the host it ran on, the beacon records it
    /// signed there go with it, and it participates from `host`, where
    /// its next seat lands. Both hosts rescan their placement on the next
    /// [`Self::topology_step`], so a placement the beacon already
    /// committed seats on `host`.
    ///
    /// Returns whether it moved: a validator attached to any host's
    /// replica, a retained terminated loop's included, stays where it
    /// runs. One serving a terminated chain with no signer attached may
    /// move.
    ///
    /// # Panics
    ///
    /// Panics if `validator` is not a registered validator.
    pub fn rehome_validator(&mut self, validator: ValidatorId, host: NodeIndex) -> bool {
        if self.hosts.iter().any(|h| h.hosts_validator(validator)) {
            return false;
        }
        let index = usize::try_from(validator.inner()).expect("id fits usize");
        let from = self.validator_home[index];
        self.hosts[from as usize].remove_participant(validator);
        self.reshape[from as usize].remove_me(validator);
        let source = Arc::clone(self.hosts[from as usize].beacon_storage());
        let destination = Arc::clone(self.hosts[host as usize].beacon_storage());
        if let Some(record) = source.beacon_vote_record(validator) {
            destination.restore_beacon_vote_record(validator, &record);
        }
        if let Some(record) = source.ratify_record(validator) {
            destination.restore_ratify_record(validator, &record);
        }
        self.validator_home[index] = host;
        self.network.bind_validator(validator, host);
        let signer = self.signer_of(validator);
        self.hosts[host as usize].add_participant(validator, signer);
        self.reshape[host as usize].add_me(validator);
        let output = self.hosts[host as usize].drain_pending_output();
        self.process_step_output(host, output);
        self.placement_epoch[from as usize] = None;
        self.placement_epoch[host as usize] = None;
        true
    }

    /// Stop hosting `shard` on `host`, returning a shared handle onto
    /// its storage so a later [`Self::join_shard`] can exercise the
    /// retained-storage fast path. The validators attached to its replica
    /// keep their beacon participants.
    ///
    /// # Panics
    ///
    /// Panics if `shard` isn't hosted on `host`.
    pub fn leave_shard(&mut self, host: NodeIndex, shard: ShardId) -> SimShardStorage {
        let shard_loop = self.hosts[host as usize]
            .remove_shard(shard)
            .expect("leave of an unhosted shard");
        (**shard_loop.io.storage()).clone()
    }

    /// Drive the [`ShardBootstrap`] sequencer to completion against the
    /// shard's serving hosts, importing into `storage`, and return the
    /// recovered state the joining replica boots from. Requests rotate
    /// across the serving hosts; a rejected chunk simply re-arms and
    /// the rotation retries it elsewhere. With `own_first`, the host's own
    /// running store answers each request before any peer is asked. Under
    /// a pending fork the completed store records that fork
    /// ([`record_fork_anchor`]) before it is handed back to be seated.
    ///
    /// Returns `None` when the shard cannot be read from a peer yet, in
    /// one of three transient shapes. No serving host holds it at all: a
    /// freshly seeded split child is a trie leaf with a committee before
    /// any of its members has mounted it, so for a moment nobody
    /// can serve it. Or a serving host holds it but no longer pins the
    /// attested boundary's state — a beacon-fold freeze at a reshape
    /// boundary can leave the anchor stale while the tip runs on, so every
    /// serving member evicts the anchor's state from its pin ring before
    /// the snap-sync can read it. Or every source still pins the state but
    /// none holds the anchor's witness window: a server prunes its
    /// persisted witnesses to the window of the anchor its own beacon
    /// attests, so a joiner whose beacon trails the committee's names an
    /// anchor whose window is already gone.
    ///
    /// A rebuild with no peer serving the shard also returns `None` the
    /// first time its own store cannot answer.
    ///
    /// Either way the caller defers the seat and retries next slice, when
    /// the committee has mounted or the anchor advanced — the
    /// deterministic counterpart of production's async
    /// `bootstrap_shard_state`, which restarts against the advanced anchor
    /// the moment it observes the boundary move.
    fn bootstrap_from_committee(
        &self,
        host: NodeIndex,
        shard: ShardId,
        anchor: ShardAnchor,
        storage: &SimShardStorage,
        own_first: bool,
    ) -> Option<RecoveredState> {
        let serving: Vec<usize> = (0..self.num_hosts())
            .filter(|&i| i != host && self.hosts_shard(i, shard).is_some())
            .map(|i| i as usize)
            .collect();
        let mut own = own_first.then(|| {
            StoreResponder::new(Arc::clone(
                self.hosts[host as usize].shard_io(shard).storage(),
            ))
        });

        // Defer if the attested anchor's state has aged out of every source's
        // pin ring; the join retries against the advanced anchor.
        let pins_anchor = |i: usize| {
            self.hosts[i]
                .shard_io(shard)
                .storage()
                .open_boundary(anchor.height)
                .is_some()
        };
        let sources = own
            .is_some()
            .then_some(host as usize)
            .into_iter()
            .chain(serving.iter().copied());
        if !sources.into_iter().any(pins_anchor) {
            return None;
        }

        // How far below the anchor this store has to reach before the
        // attested window folds can answer — off the same schedule
        // projection the folds read their own floor from.
        let topology = self.hosts[host as usize].process().topology_snapshot();
        let floor = history_floor(
            anchor.weighted_timestamp,
            topology.load().settled_window_floor(shard),
        );
        let peers: Vec<StoreResponder<SimShardStorage>> = serving
            .iter()
            .map(|&i| StoreResponder::new(Arc::clone(self.hosts[i].shard_io(shard).storage())))
            .collect();
        let anchor_qc = topology
            .load()
            .boundary_qc(shard)
            .filter(|qc| qc.block_hash() == anchor.block_hash)
            .cloned();
        let mut bootstrap = ShardBootstrap::new(shard, anchor, anchor_qc, floor);
        let mut peer = 0usize;
        // Consecutive witness pages every source declined. The pump runs
        // inside one step, so a page the whole rotation declined is never
        // served; nothing is staged before the witness window verifies.
        let mut witness_declines = 0usize;
        for _ in 0..MAX_BOOTSTRAP_ROUNDS {
            if bootstrap.is_complete() {
                break;
            }
            if let Some((height, witnesses)) = bootstrap.take_finalize() {
                let root = storage
                    .finalize_boundary_import(height, witnesses)
                    .expect("boundary import into a fresh store");
                bootstrap
                    .on_imported(root)
                    .expect("imported root matches the attested anchor");
                bootstrap.reach_unresolved(&storage.member_index(shard));
                continue;
            }
            for request in bootstrap.next_requests() {
                // The history walk's window asks below the block that ends it.
                if bootstrap.is_complete() {
                    break;
                }
                if let Some(response) = own.as_ref().and_then(|own| own.answer(&request)) {
                    // A store forked at or below the anchor answers off the
                    // attested chain; peers answer everything from then on.
                    if !bootstrap
                        .absorb(&response, storage)
                        .expect("staging into a fresh store")
                    {
                        own = None;
                    }
                    continue;
                }
                if peers.is_empty() {
                    return None;
                }
                let answer = ask_peers(&peers, peer, &request);
                peer += 1;
                let Some(response) = answer else {
                    witness_declines +=
                        usize::from(matches!(request, BootstrapRequest::WitnessHistory(_)));
                    if witness_declines >= peers.len() {
                        return None;
                    }
                    bootstrap.on_request_failure(&request);
                    continue;
                };
                witness_declines = 0;
                bootstrap
                    .absorb(&response, storage)
                    .expect("staging into a fresh store");
            }
        }
        assert!(
            bootstrap.is_complete(),
            "snap-sync bootstrap for shard {shard:?} did not complete against a pinned anchor",
        );
        record_fork_anchor(storage, &topology.load(), shard);
        Some(bootstrap.into_recovered_state(storage))
    }

    /// Mount `shard` on `host` over `storage`, booted from `recovered`
    /// with `validators` attached: the chain registers with the host's
    /// beacon loop and its replica is built from the schedule the
    /// registration hands back — the same construction the production
    /// supervisor runs at seat time.
    pub(super) fn add_shard(
        &mut self,
        host: NodeIndex,
        shard: ShardId,
        validators: &[ValidatorId],
        storage: SimShardStorage,
        recovered: &RecoveredState,
    ) {
        let config = self.replica_config(host);
        let signers = validators
            .iter()
            .map(|&validator| (validator, self.signer_of(validator)))
            .collect();
        let sender = self.event_txs[host as usize].clone();
        self.hosts[host as usize].add_shard(
            &config,
            HostedChain {
                shard,
                storage,
                recovered,
                signers,
            },
            sender,
        );
    }

    /// How `host` builds every replica it runs at runtime.
    fn replica_config(&self, host: NodeIndex) -> ReplicaConfig {
        let host = &self.hosts[host as usize];
        ReplicaConfig {
            verifier: Arc::clone(&self.verifier),
            derivation: host.derivation(),
            code: host.code(),
            beacon_network: self.beacon_network.clone(),
            beacon_config_hash: self.beacon_config_hash,
            shard_config: ShardConsensusConfig::default(),
            mempool_config: MempoolConfig::default(),
            provision_config: ProvisionConfig::default(),
        }
    }

    /// `validator`'s signer.
    pub(super) fn signer_of(&self, validator: ValidatorId) -> Arc<dyn Signer> {
        Arc::clone(&self.signers[usize::try_from(validator.inner()).expect("id fits usize")])
    }
}
