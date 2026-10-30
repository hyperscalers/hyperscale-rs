//! The supervisor's membership half: bring shards up and tear them down
//! against the committed beacon placement.
//!
//! A join opens storage off the loop, snap-syncs a fresh store against the
//! beacon-attested anchor (parking until this host's topology carries one,
//! unless the shard's chain runs from network genesis), and runs the shard's
//! replica, with its local validators attached as signers, on a new pinned
//! thread; a leave refcounts memberships down and tears the thread, maps, and
//! storage down at zero. [`ShardSupervisor::reconcile_seats`] drives
//! membership from committed state, carrying out the seat changes
//! [`reconcile`] plans.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, Weak};
use std::time::{Duration, Instant};

use hyperscale_beacon::ChainRegistration;
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_node::host::{attach_shard, chain_anchors, detach_shard};
use hyperscale_node::seating::{
    HostedView, Replaced, SeatChange, Wipe, join_wipe, placed_validators, reconcile, reseat,
    seat_running, seat_validators,
};
use hyperscale_node::shard::{BeaconScopedInput, HostEvent};
use hyperscale_node::{
    HostedChain, Registration, RegistrationReply, ReplicaConfig, installed_network_genesis_block,
    network_genesis_block,
};
use hyperscale_storage::{RecoveredState, ShardChainReader, SubstateStore, carry_signed_rounds};
use hyperscale_storage_rocksdb::{RocksDbShardStorage, rename_durably};
use hyperscale_types::{
    Block, BlockHeight, ShardId, TopologySchedule, TopologySnapshot, ValidatorId,
};
use tokio::task::spawn_blocking;
use tokio::time::sleep;
use tracing::{info, warn};

use super::reshape::reshape_owns;
#[cfg(feature = "test-utils")]
use super::seats::LeaveStep;
use super::seats::{Departing, Drained, JoinStep, RebuiltStep, Registering};
use super::{LoopStart, ShardSupervisor, SupervisorEvent};
use crate::bootstrap::bootstrap_shard_state;
use crate::runner::VnodeConfig;
use crate::shard_thread::{ShardChannels, ShardControl};

/// A finished snap-sync bootstrap, ready for the supervisor to seat:
/// the imported storage verified against the attested anchor, plus the
/// recovered state the shard's replica boots from.
pub struct CompletedBootstrap {
    shard: ShardId,
    vnodes: Vec<VnodeConfig>,
    storage: Arc<RocksDbShardStorage>,
    recovered: RecoveredState,
}

impl ShardSupervisor {
    /// Bring up `shard`: open its storage off this loop, then continue
    /// in [`Self::on_opened`] — seat directly for a retained store or a
    /// genesis replay, snap-sync against the beacon-attested anchor
    /// first, or park until the anchor reaches this host. A join for a
    /// shard still tearing down queues and replays once the teardown
    /// finishes; one for a shard already running seats into its loop,
    /// one for a shard whose seat is registering seats with it, and one
    /// for a shard parked on its anchor joins the parked vnodes.
    pub(super) fn join(&mut self, shard: ShardId, vnodes: &[VnodeConfig]) {
        if vnodes.is_empty() || vnodes.iter().any(|v| v.local_shard != shard) {
            warn!(shard = ?shard, "Join rejected: vnodes must be non-empty and target the shard");
            return;
        }
        // A reshape duty owns seating this shard — a merge's keepers
        // reforming the parent, or a split's children, surfaced as an ordinary
        // join when the reshape executes. The orchestrator seats them from the
        // prepared store (which carries the reshape's terminal/merged state),
        // so a join for it is a no-op here. The four conditions span the
        // duty's whole lifetime so the join never opens a `RocksDB`
        // directory the duty is using — `RocksDB`'s exclusive lock fails the
        // second opener outright, so an overlap strands a co-hosted committee
        // member's seat. `is_seating` reads the orchestrator's post-discovery
        // state; `reshape_owns` reads the committed projection, covering the
        // window before discovery runs and while the cohort is still published;
        // `reshape_stores` covers the late window after the beacon marks the
        // successor live (clearing the cohort, so `reshape_owns` lapses) while
        // the duty still holds the opened store between its open and seat; and
        // the seat table's held prep covers a prep parked behind an earlier
        // open.
        let claimed = || {
            self.reshape.is_seating(shard)
                || reshape_owns(&self.reshape, &self.process, &self.vnode_keys, shard)
                || self.reshape_stores.contains(shard)
        };
        match self.seats.join(shard, vnodes, claimed) {
            JoinStep::Rejected => {
                warn!(shard = ?shard, "Join rejected: shard still bootstrapping");
                return;
            }
            JoinStep::Queued { replaced } => {
                info!(shard = ?shard, "Join queued behind the shard's in-flight teardown");
                if replaced {
                    warn!(shard = ?shard, "Replaced an earlier queued join for the shard");
                }
                return;
            }
            JoinStep::Superseded => {
                info!(shard = ?shard, "Join superseded by an active reshape duty; the orchestrator seats it");
                return;
            }
            JoinStep::Registering => {
                info!(shard = ?shard, "Join seats with the shard's in-flight registration");
                return;
            }
            JoinStep::OnRunning => {
                self.seat_on_running(shard, vnodes);
                return;
            }
            JoinStep::Parked => {
                info!(shard = ?shard, "Join parked with the shard's others awaiting its anchor");
                return;
            }
            JoinStep::Open => {}
        }

        // The RocksDB open (and a previously-used store's recovery
        // read) can stall on disk; run it off the loop and continue in
        // `on_opened`. The pending seat blocks double joins and lets a
        // `Leave` during the open release memberships.
        let factory = Arc::clone(&self.storage_factory);
        let dir = (self.storage_dir)(shard);
        let engine_bootstrap = self.engine_bootstrap.clone();
        let events = self.events_tx.clone();
        let vnodes = vnodes.to_vec();
        let schedule = self.process.topology_schedule();
        self.tokio_handle.spawn_blocking(move || {
            let outcome = factory(&dir, shard).and_then(|storage| {
                // A store [`join_wipe`] wipes is dropped, and the join
                // starts from nothing.
                match join_wipe(storage.as_ref(), shard, &schedule) {
                    None => return Ok(storage),
                    Some(Wipe::Recovered) => {
                        info!(shard = ?shard, "Join wiping a store a recovery leaves behind");
                    }
                    Some(Wipe::Unadopted) => {
                        info!(shard = ?shard, "Join wiping a reshape store its duty never adopted");
                    }
                }
                drop(storage);
                std::fs::remove_dir_all(&dir).map_err(|e| format!("unadopted store wipe: {e}"))?;
                factory(&dir, shard)
            });
            let outcome = outcome.map(|storage| {
                let recovered = storage.load_recovered_state(shard);
                // A brand-new store (no installed genesis, no commits)
                // gets the engine bootstrap before the snap-sync import
                // or the genesis install populates it.
                if storage.is_fresh() {
                    engine_bootstrap.replicate_into(storage.as_ref());
                }
                (storage, recovered)
            });
            // Send failure means the runner is shutting down; the join
            // dies with it.
            let _ = events.send(SupervisorEvent::Opened {
                shard,
                vnodes,
                outcome,
            });
        });
    }

    /// Continue a join whose storage open finished.
    ///
    /// Five paths by what the store and this host's topology offer:
    /// - **retained storage** (a committed block past genesis) — seat
    ///   directly; normal block sync covers the tail;
    /// - **installed network genesis, nothing committed past it** — the
    ///   host crashed between the genesis install and block 1: seat on the
    ///   genesis the store holds, exactly as its first run would have, and
    ///   let block sync carry the chain forward;
    /// - **fresh store, attested anchor** — snap-sync bootstrap off
    ///   this loop (a tokio task), seated via [`Self::finish_join`]
    ///   when the import verifies against the anchor;
    /// - **fresh store, genesis-born shard with no crossing yet** — install
    ///   the network genesis the shard's members committed at birth, seat on
    ///   it, and let block sync carry the chain forward from there;
    /// - **fresh store, no anchor otherwise** — the shard's chain began
    ///   past genesis, or has crossed a boundary this host's topology has
    ///   not yet folded, so a genesis replay has nothing to start from.
    ///   The store is dropped unseated and the join parks in
    ///   `awaiting_anchor`, retried by [`Self::reconcile_seats`] once the
    ///   anchor arrives.
    pub(super) fn on_opened(
        &mut self,
        shard: ShardId,
        mut vnodes: Vec<VnodeConfig>,
        outcome: Result<(Arc<RocksDbShardStorage>, RecoveredState), String>,
    ) {
        let Some(pending) = self.seats.opened(shard) else {
            info!(shard = ?shard, "Storage opened for an abandoned join; dropped");
            return;
        };
        let (storage, recovered) = match outcome {
            Ok(opened) => opened,
            Err(error) => {
                self.seats.abandon_join(shard);
                warn!(shard = ?shard, error, "Join rejected: storage open failed");
                return;
            }
        };
        // A reshape duty has since claimed this shard — the join slipped past
        // the `reshape_owns` suppression against a stale snapshot and opened the
        // store anyway. Drop it (releasing the `RocksDB` lock) and let the duty
        // seat the shard from its terminal/merged store; any prep held behind
        // this open can now run.
        if reshape_owns(&self.reshape, &self.process, &self.vnode_keys, shard) {
            self.seats.abandon_join(shard);
            drop(storage);
            info!(shard = ?shard, "Join abandoned to its reshape duty after the store opened");
            self.resume_pending_reshape_prep();
            return;
        }
        // A vnode that left during the open is not seated.
        vnodes.retain(|vnode| pending.contains(&vnode.validator_id));

        let fresh_store = storage.is_fresh();
        let topology_snapshot = self.process.topology_snapshot().load_full();
        if fresh_store && topology_snapshot.boundary(shard).is_some() {
            let process = Arc::clone(&self.process);
            let events = self.events_tx.clone();
            let gauge = self.publishers.importing.gauge(shard);
            self.tokio_handle.spawn(async move {
                let done = match bootstrap_shard_state(
                    process.network(),
                    process.topology_snapshot(),
                    &storage,
                    shard,
                    None,
                    gauge,
                )
                .await
                {
                    Ok(recovered) => Ok(CompletedBootstrap {
                        shard,
                        vnodes,
                        storage,
                        recovered,
                    }),
                    Err(error) => {
                        warn!(shard = ?shard, error, "Shard bootstrap failed; join abandoned");
                        Err(shard)
                    }
                };
                // Send failure means the runner is shutting down; the
                // join dies with it.
                let _ = events.send(SupervisorEvent::Bootstrapped(done));
            });
            return;
        }
        if !fresh_store && recovered.committed_height == BlockHeight::GENESIS {
            let genesis = installed_network_genesis_block(
                shard,
                storage.state_root(),
                self.process.topology_schedule().windows().origin(),
            );
            info!(
                shard = ?shard,
                genesis_hash = ?genesis.hash(),
                "Seating a store at the network genesis it installed"
            );
            self.seat_shard_with_genesis(shard, &vnodes, storage, &recovered, Some(&genesis));
            return;
        }
        if !fresh_store {
            self.seat_shard(shard, &vnodes, storage, &recovered);
            return;
        }
        if !topology_snapshot.genesis_unanchored(shard) {
            drop(storage);
            info!(shard = ?shard, "Join parked until this host's topology carries the shard's anchor");
            self.seats.park(shard, vnodes);
            return;
        }
        let genesis = network_genesis_block(
            storage.as_ref(),
            shard,
            &topology_snapshot,
            &self.engine_bootstrap.config,
            self.process.topology_schedule().windows().origin(),
        );
        info!(
            shard = ?shard,
            genesis_hash = ?genesis.hash(),
            state_root = ?genesis.header().state_root(),
            "Seating a fresh store at the network genesis"
        );
        self.seat_shard_with_genesis(shard, &vnodes, storage, &recovered, Some(&genesis));
    }

    /// Settle a finished bootstrap: seat the shard on success, clear
    /// the bootstrapping entry on failure (so a later reconcile can
    /// retry the join), drop the outcome when every pending vnode
    /// left during the bootstrap. Runs on the runner's loop via the
    /// completion channel — never on the bootstrap task.
    pub(super) fn finish_join(&mut self, done: Result<CompletedBootstrap, ShardId>) {
        let shard = match &done {
            Ok(done) => done.shard,
            Err(shard) => *shard,
        };
        let Some(pending) = self.seats.synced(shard) else {
            info!(shard = ?shard, "Bootstrap finished for an abandoned join; dropped");
            return;
        };
        let Ok(mut done) = done else {
            // Failure already logged by the bootstrap task.
            return;
        };
        if self.seats.is_running(shard) {
            warn!(shard = ?shard, "Bootstrap completed for an already-hosted shard; dropped");
            return;
        }
        done.vnodes
            .retain(|vnode| pending.contains(&vnode.validator_id));
        self.seat_shard(shard, &done.vnodes, done.storage, &done.recovered);
    }

    /// Wire a shard's validators into the process maps and spawn its
    /// pinned thread, booting the replica from `recovered`.
    fn seat_shard(
        &mut self,
        shard: ShardId,
        vnodes: &[VnodeConfig],
        storage: Arc<RocksDbShardStorage>,
        recovered: &RecoveredState,
    ) {
        self.seat_shard_with_genesis(shard, vnodes, storage, recovered, None);
    }

    /// [`Self::seat_shard`] with an optional pre-spawn genesis install,
    /// committed through the freshly attached loop before the thread
    /// spawns: a split child's flip commits its derived genesis, and a
    /// fresh store on a never-crossed genesis shard the network's.
    ///
    /// The chain registers with the host's beacon loop first, and the
    /// loop is built only once the registration comes back, from the
    /// schedule it carries: the join stays pending across the reply,
    /// as it does across a bootstrap, and a leave meanwhile releases it.
    pub(super) fn seat_shard_with_genesis(
        &mut self,
        shard: ShardId,
        vnodes: &[VnodeConfig],
        storage: Arc<RocksDbShardStorage>,
        recovered: &RecoveredState,
        genesis: Option<&Block>,
    ) {
        let (channels, callback_tx) = ShardChannels::new();
        let seat = self.seats.register(Registering {
            shard,
            vnodes: vnodes.to_vec(),
            storage,
            recovered: recovered.clone(),
            genesis: genesis.cloned(),
            channels,
            sender: callback_tx.clone(),
        });
        let events = self.events_tx.clone();
        let reply = RegistrationReply(Arc::new(move |registration| {
            // Send failure means the runner is shutting down.
            let _ = events.send(SupervisorEvent::Registered {
                shard,
                seat,
                registration,
            });
        }));
        let _ = self.process.beacon_event_sender().send(HostEvent::Beacon(
            BeaconScopedInput::Register {
                shard,
                anchors: chain_anchors(recovered),
                height: recovered.committed_height,
                sender: callback_tx,
                reply,
            },
        ));
    }

    /// A chain's registration came back: build its loop from the schedule
    /// it carries, commit its genesis or restore its committed state, and
    /// spawn it. A seat a later one superseded, or one every vnode left
    /// meanwhile, is gone, and its registration is released. A reshape
    /// store-prep held behind the seat runs once it settles.
    pub(super) fn on_registered(&mut self, shard: ShardId, seat: u64, registration: &Registration) {
        if let Some((pending, ids)) = self.seats.registered(shard, seat) {
            self.seat_registered(pending, &ids, registration);
        } else {
            info!(shard = ?shard, "Registration came back for an abandoned seat; released");
            self.deregister(registration.token);
        }
        self.resume_pending_reshape_prep();
    }

    /// Build and spawn a registered seat's loop over the vnodes still
    /// pending.
    fn seat_registered(
        &mut self,
        pending: Registering,
        ids: &BTreeSet<ValidatorId>,
        registration: &Registration,
    ) {
        let Registering {
            shard,
            mut vnodes,
            storage,
            recovered,
            genesis,
            channels,
            sender,
        } = pending;
        vnodes.retain(|vnode| ids.contains(&vnode.validator_id));
        let seated = vnodes.len();
        let shard_loop = attach_shard(
            &self.process,
            &self.node_config,
            &self.replica_config(),
            registration,
            HostedChain {
                shard,
                storage: (*storage).clone(),
                recovered: &recovered,
                signers: vnodes
                    .iter()
                    .map(|vnode| (vnode.validator_id, Arc::clone(&vnode.signer)))
                    .collect(),
            },
            sender,
        );
        let start = genesis
            .as_ref()
            .map_or(LoopStart::Resume(&recovered), LoopStart::Genesis);
        self.start_loop(shard_loop, channels, start);
        self.storages
            .lock()
            .expect("storages lock")
            .insert(shard, storage);
        info!(shard = ?shard, vnodes = seated, "Shard joined at runtime");
    }

    /// Release a chain's registration with the host's beacon loop.
    fn deregister(&self, token: ChainRegistration) {
        let _ = self
            .process
            .beacon_event_sender()
            .send(HostEvent::Beacon(BeaconScopedInput::Deregister(token)));
    }

    /// Seat `vnodes` on `shard`'s running loop as [`seat_running`] plans:
    /// rebuild the loop first where its store cannot carry them. A shard
    /// already rebuilding seats every placed validator when its swap lands.
    fn seat_on_running(&mut self, shard: ShardId, vnodes: &[VnodeConfig]) {
        if self.seats.is_rebuilding(shard) {
            return;
        }
        let placed = vnodes.iter().map(|vnode| vnode.validator_id).collect();
        let schedule = self.process.topology_schedule();
        let running = self.running_seats();
        let storages = self.storages.lock().expect("storages lock");
        let Some(view) = hosted_views(running, &storages)
            .into_iter()
            .find(|view| view.shard == shard)
        else {
            return;
        };
        let head = self.process.topology_snapshot().load_full();
        let changes = seat_running(&view, &head, schedule.windows(), placed);
        drop(storages);
        for change in changes {
            self.apply_seat_change(change);
        }
    }

    /// Re-seat `shard` at its attested anchor ([`reseat`]): its loop needs
    /// a height beneath every serving peer's chain floor, so block sync
    /// cannot carry the store forward and a snap-sync must. A shard already
    /// rebuilding, bootstrapping, or not running here has nothing to
    /// re-seat, and one with no attested anchor has nothing to re-seat on.
    pub(super) fn reseat(&mut self, shard: ShardId) {
        let Some(carried) = self.seats.reseatable(shard) else {
            return;
        };
        let local: HashSet<ValidatorId> = self.vnode_keys.keys().copied().collect();
        let schedule = self.process.topology_schedule();
        let head = self.process.topology_snapshot().load_full();
        let Some(change) = reseat(shard, &schedule, &head, &carried, &local) else {
            warn!(shard = ?shard, "Store beneath every peer's chain floor, and no attested anchor to re-seat on");
            return;
        };
        info!(shard = ?shard, "Re-seating a store beneath every peer's chain floor");
        self.apply_seat_change(change);
    }

    /// Rebuild `shard` at its attested anchor, make before break: a
    /// staging store beside the shard's directory snap-syncs while the old
    /// loop keeps running and serving, reading the old store first and
    /// peers for what it no longer holds. [`Self::on_rebuilt`] swaps it
    /// in.
    fn rebuild(&mut self, shard: ShardId, vnodes: &[VnodeConfig], replaced: Replaced) {
        let old = self
            .storages
            .lock()
            .expect("storages lock")
            .get(&shard)
            .cloned();
        let Some(old) = old else {
            return;
        };
        let number = self.seats.start_rebuild(shard);
        info!(shard = ?shard, "Rebuilding the shard's store at its attested anchor");
        let staging_dir = staging_dir(&(self.storage_dir)(shard));
        let factory = Arc::clone(&self.storage_factory);
        let engine_bootstrap = self.engine_bootstrap.clone();
        let process = Arc::clone(&self.process);
        let events = self.events_tx.clone();
        let vnodes = vnodes.to_vec();
        let gauge = self.publishers.importing.gauge(shard);
        self.tokio_handle.spawn(async move {
            let opened = spawn_blocking(move || {
                // A staging directory an interrupted rebuild left behind
                // is no store anything reads; start from nothing.
                if staging_dir.exists() {
                    std::fs::remove_dir_all(&staging_dir)
                        .map_err(|e| format!("stale staging store wipe: {e}"))?;
                }
                let storage = factory(&staging_dir, shard)?;
                engine_bootstrap.replicate_into(storage.as_ref());
                Ok::<_, String>(storage)
            })
            .await
            .map_err(|e| format!("staging open task died: {e}"))
            .flatten();
            let staged = match opened {
                Ok(storage) => bootstrap_shard_state(
                    process.network(),
                    process.topology_snapshot(),
                    &storage,
                    shard,
                    Some(old),
                    gauge,
                )
                .await
                .map(|recovered| CompletedBootstrap {
                    shard,
                    vnodes,
                    storage,
                    recovered,
                }),
                Err(error) => Err(error),
            };
            let outcome = staged.map_err(|error| {
                warn!(shard = ?shard, error, "Shard rebuild failed; its loop keeps running");
                shard
            });
            // Send failure means the runner is shutting down; the rebuild
            // dies with it.
            let _ = events.send(SupervisorEvent::Rebuilt {
                rebuild: number,
                outcome,
                replaced,
            });
        });
    }

    /// Settle a rebuild's staging: tear the old loop down, and seat on the
    /// staging store every local validator placed on the shard, the
    /// joiner that triggered the rebuild included, once
    /// [`Self::on_torn_down`] has renamed it into place. A validator the
    /// old loop carried and the shard no longer places follows the beacon
    /// on the beacon loop, as any drained validator does.
    ///
    /// Only the rebuild the shard is still staging settles. One a teardown
    /// superseded, or a later rebuild of a re-seated loop, drops its staging
    /// store and leaves the directory, which every rebuild of the shard
    /// shares and the next one wipes at its open: a later rebuild may be
    /// syncing into it, or a later swap renaming it into place.
    pub(super) fn on_rebuilt(
        &mut self,
        rebuild: u64,
        outcome: Result<CompletedBootstrap, ShardId>,
        replaced: Replaced,
    ) {
        let shard = match &outcome {
            Ok(done) => done.shard,
            Err(shard) => *shard,
        };
        let mut done = match (self.seats.rebuilt(shard, rebuild, outcome.is_ok()), outcome) {
            (RebuiltStep::Swap, Ok(done)) => done,
            (RebuiltStep::Superseded, outcome) => {
                info!(shard = ?shard, rebuild, "A superseded rebuild settled; its staging store dropped");
                self.drop_staged(outcome);
                return;
            }
            // Failed, or torn down while the staging store synced: nothing
            // to swap.
            (_, outcome) => {
                self.drop_staged(outcome);
                return;
            }
        };
        let schedule = self.process.topology_schedule();
        let mut vnodes = self.placed_vnodes(&schedule, shard);
        for joiner in std::mem::take(&mut done.vnodes) {
            if !vnodes.iter().any(|v| v.validator_id == joiner.validator_id) {
                vnodes.push(joiner);
            }
        }
        done.vnodes = vnodes;
        self.seats.swap(shard, Box::new(done), replaced);
        self.tear_down(shard);
    }

    /// Close a staging store no swap takes, off the loop.
    fn drop_staged(&self, outcome: Result<CompletedBootstrap, ShardId>) {
        if let Ok(done) = outcome {
            self.tokio_handle.spawn_blocking(move || drop(done));
        }
    }

    /// Replace `shard`'s store with its rebuilt one and seat it: carry the
    /// rounds signed on an old store that fell behind, whose loop has
    /// joined, onto the rebuilt one, and once the old store's last handle
    /// is gone, remove its directory, rename the staging directory into
    /// its place, and reopen it there, settling through
    /// [`Self::finish_join`] as a snap-synced join does.
    fn swap_rebuilt(
        &mut self,
        done: CompletedBootstrap,
        old: Option<Arc<RocksDbShardStorage>>,
        replaced: Replaced,
    ) {
        let CompletedBootstrap {
            shard,
            vnodes,
            storage,
            recovered,
        } = done;
        self.seats.sync(shard, &vnodes);
        let dir = (self.storage_dir)(shard);
        let factory = Arc::clone(&self.storage_factory);
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            let old = old.map(|old| {
                if replaced == Replaced::Behind {
                    carry_signed_rounds(old.as_ref(), storage.as_ref());
                }
                Arc::downgrade(&old)
            });
            drop(storage);
            let outcome = (|| -> Result<Arc<RocksDbShardStorage>, String> {
                await_release(old);
                if dir.exists() {
                    std::fs::remove_dir_all(&dir)
                        .map_err(|e| format!("replaced store removal: {e}"))?;
                }
                rename_durably(&staging_dir(&dir), &dir)
                    .map_err(|e| format!("rebuilt store rename: {e}"))?;
                factory(&dir, shard)
            })();
            let done = outcome
                .map(|storage| {
                    info!(
                        shard = ?shard,
                        committed = recovered.committed_height.inner(),
                        "Shard rebuilt at its attested anchor"
                    );
                    CompletedBootstrap {
                        shard,
                        vnodes,
                        storage,
                        recovered,
                    }
                })
                .map_err(|error| {
                    warn!(shard = ?shard, error, "Rebuilt store swap failed; join abandoned");
                    shard
                });
            // Send failure means the runner is shutting down.
            let _ = events.send(SupervisorEvent::Bootstrapped(done));
        });
    }

    /// Attach each of `vnodes` the running replica of `shard` does not
    /// already carry or have queued: a validator drawn onto a shard this
    /// host serves signs through its replica rather than a thread of its
    /// own. The loop attaches it in the step that takes the control and
    /// reports it back as [`SupervisorEvent::Attached`].
    fn seat_into_running(&mut self, shard: ShardId, vnodes: &[VnodeConfig]) {
        let Some(entry) = self.seats.thread_mut(shard) else {
            return;
        };
        for vnode in vnodes {
            let id = vnode.validator_id.inner();
            if entry.validator_ids.contains(&id) || entry.queued.contains(&id) {
                continue;
            }
            let attach = ShardControl::Attach(vnode.validator_id, Arc::clone(&vnode.signer));
            if entry.control_tx.send(attach).is_ok() {
                entry.queued.push(id);
                info!(shard = ?shard, validator = id, "Attach sent to a running shard");
            }
        }
    }

    /// A running loop attached a validator: count it among the shard's.
    /// One that left while its attach was in flight is not counted: its
    /// leave sent the loop a detach behind the attach.
    pub(super) fn on_attached(&mut self, shard: ShardId, validator: ValidatorId) {
        let Some(entry) = self.seats.thread_mut(shard) else {
            return;
        };
        let id = validator.inner();
        if !entry.queued.contains(&id) {
            return;
        }
        entry.queued.retain(|&queued| queued != id);
        if !entry.validator_ids.contains(&id) {
            entry.validator_ids.push(id);
        }
        info!(shard = ?shard, validator = id, "Signer attached on a running shard");
    }

    /// Release `validator`'s membership in `shard`; tear the shard down
    /// when it was the last. A leave that lands while the shard's join is
    /// still bootstrapping, or parked on its anchor, releases that pending
    /// membership instead, abandoning the join when the last one goes.
    #[cfg(feature = "test-utils")]
    pub(super) fn leave(&mut self, shard: ShardId, validator: ValidatorId) {
        match self.seats.leave(shard, validator) {
            LeaveStep::Abandoned => {
                info!(shard = ?shard, "Last pending signer left during bootstrap; join abandoned");
                self.resume_pending_reshape_prep();
                return;
            }
            LeaveStep::Continues { remaining } => {
                info!(
                    shard = ?shard,
                    remaining,
                    "Signer left during bootstrap; join continues for the remaining signers"
                );
                return;
            }
            LeaveStep::Unparked { abandoned } => {
                if abandoned {
                    info!(shard = ?shard, "Last parked vnode left; join awaiting the anchor abandoned");
                }
                return;
            }
            LeaveStep::NotPending => {}
        }
        let Some(entry) = self.seats.thread_mut(shard) else {
            warn!(shard = ?shard, "Leave rejected: shard not hosted");
            return;
        };
        let id = validator.inner();
        if !entry.validator_ids.contains(&id) && !entry.queued.contains(&id) {
            warn!(shard = ?shard, validator = id, "Leave rejected: validator not attached on the shard");
            return;
        }
        let others = entry
            .validator_ids
            .iter()
            .chain(&entry.queued)
            .any(|&other| other != id);
        if !others {
            self.tear_down(shard);
            return;
        }
        // Behind any attach of it still on the same channel, so the loop
        // detaches what it attached.
        if entry
            .control_tx
            .send(ShardControl::Detach(validator))
            .is_err()
        {
            return;
        }
        entry.validator_ids.retain(|&kept| kept != id);
        entry.queued.retain(|&kept| kept != id);
        info!(
            shard = ?shard,
            validator = id,
            remaining = entry.validator_ids.len(),
            "Signer detached; shard stays up for its remaining signers"
        );
    }

    /// Tear a hosted shard's thread down and unwire it off the loop:
    /// signal shutdown, drop the entry, and join the thread off-loop,
    /// finishing the unwire in [`Self::on_torn_down`]. Shared by the
    /// [`Self::leave`] of the last signer and the
    /// reshape-tick routable-expiry reconcile.
    fn tear_down(&mut self, shard: ShardId) {
        let Some(Departing {
            shutdown_tx,
            draining,
            validator_ids,
        }) = self.seats.tear_down(shard)
        else {
            return;
        };
        let _ = shutdown_tx.send(());
        // The thread join waits out an in-flight shard step; run it off
        // the loop and finish the unwire in `on_torn_down`.
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            let join = draining
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(join) = join
                && join.join().is_err()
            {
                warn!(shard = ?shard, "Shard thread panicked before teardown");
            }
            // Send failure means the runner is shutting down; the
            // teardown finishes with it.
            let _ = events.send(SupervisorEvent::TornDown {
                shard,
                validator_ids,
            });
        });
    }

    /// Reconcile hosted shards against the committed view, carrying out
    /// the changes [`reconcile`] plans. A join parked on its shard's anchor
    /// is retried first, once this host's topology carries it.
    ///
    /// A loop that is rebuilding or that a reshape duty is seating gains no
    /// seat here; a shard opening, draining, parked, seated by a reshape
    /// duty, or holding a store one prepared is not joined. Idempotent: the
    /// plan skips every shard already accounted for, and [`Self::join`]
    /// rejects a double bring-up regardless. Run on the reshape tick, after
    /// the reshape duties, binding serving and routing to one committed
    /// lifetime in place of a fixed drain grace.
    pub(crate) fn reconcile_seats(&mut self) {
        let topology_snapshot = self.process.topology_snapshot().load_full();
        let anchored = self.seats.unpark(|shard| {
            topology_snapshot.boundary(shard).is_some()
                || topology_snapshot.genesis_unanchored(shard)
        });
        for (shard, vnodes) in anchored {
            info!(shard = ?shard, "Retrying a join parked on its anchor");
            self.join(shard, &vnodes);
        }
        let schedule = self.process.topology_schedule();
        let routing = self.process.network().routing_committees();
        let local: HashSet<ValidatorId> = self.vnode_keys.keys().copied().collect();
        let running = self.running_seats();
        let storages = self.storages.lock().expect("storages lock");
        let hosted = hosted_views(running, &storages);
        let changes = reconcile(
            &schedule,
            &topology_snapshot,
            &routing,
            &hosted,
            &local,
            |shard| {
                self.seats.vacant(shard)
                    && !self.reshape.is_seating(shard)
                    && !self.reshape_stores.contains(shard)
            },
        );
        drop(storages);
        for change in changes {
            self.apply_seat_change(change);
        }
    }

    /// Every running loop's seats as the seating plan reads them: its
    /// shard, the validators attached and attaching, and whether the plan
    /// may seat more on it.
    fn running_seats(&mut self) -> Vec<RunningSeats> {
        let ids = |ids: &[u64]| ids.iter().copied().map(ValidatorId::new).collect();
        let shards: Vec<ShardId> = self.seats.running().collect();
        let mut running = Vec::with_capacity(shards.len());
        for shard in shards {
            let seatable = !self.seats.is_rebuilding(shard) && !self.reshape.is_seating(shard);
            if let Some(entry) = self.seats.thread_mut(shard) {
                running.push((
                    shard,
                    ids(&entry.validator_ids),
                    ids(&entry.queued),
                    seatable,
                ));
            }
        }
        running
    }

    /// Carry out one planned seat change.
    fn apply_seat_change(&mut self, change: SeatChange) {
        match change {
            SeatChange::Retire(shard) => {
                info!(
                    shard = ?shard,
                    "Shard aged out of the routable window; tearing down"
                );
                self.tear_down(shard);
            }
            SeatChange::Detach(shard, validator) => {
                let Some(entry) = self.seats.thread_mut(shard) else {
                    return;
                };
                if entry
                    .control_tx
                    .send(ShardControl::Detach(validator))
                    .is_ok()
                {
                    entry
                        .validator_ids
                        .retain(|&kept| kept != validator.inner());
                    info!(
                        shard = ?shard,
                        validator = validator.inner(),
                        "Signer detached from a running shard"
                    );
                }
            }
            SeatChange::Rebuild {
                shard,
                seats,
                replaced,
            } => {
                let vnodes = self.vnodes(shard, &seats);
                self.rebuild(shard, &vnodes, replaced);
            }
            SeatChange::Attach(shard, validator) => {
                let vnodes = self.vnodes(shard, &[validator]);
                self.seat_into_running(shard, &vnodes);
            }
            SeatChange::Join(shard, validators) => {
                info!(shard = ?shard, "Joining a shard the committed view places a local validator on");
                let vnodes = self.vnodes(shard, &validators);
                self.join(shard, &vnodes);
            }
        }
    }

    /// Finish a teardown whose thread joined: unwire the process maps,
    /// drop the storage handle, scrub the RPC slots, and replay any
    /// join that queued behind the drain. A drain that carries a rebuild's
    /// swap seats the queued join's validators with the swap, whose
    /// `bootstrapping` entry would otherwise reject the replay. A reshape
    /// store-prep held behind the drain runs once it settles.
    pub(super) fn on_torn_down(&mut self, shard: ShardId, validator_ids: &[u64]) {
        detach_shard(&self.process, shard);
        let storage = self.storages.lock().expect("storages lock").remove(&shard);
        if let Some(storage) = &storage {
            // A store handle that outlives its teardown holds the RocksDB
            // directory lock, and every later re-seat of this host onto the
            // shard fails its storage open until the process restarts. That
            // failure is silent at the leak site and surfaces minutes or
            // days later as a join-retry loop, so probe for it: transient
            // holders (an in-flight GC pass, a serving request) drain in
            // well under the grace.
            let probe = Arc::downgrade(storage);
            self.tokio_handle.spawn(async move {
                sleep(Duration::from_secs(5)).await;
                if let Some(live) = probe.upgrade() {
                    warn!(
                        shard = ?shard,
                        holders = Arc::strong_count(&live).saturating_sub(1),
                        "Shard store handle still held after teardown; its RocksDB lock is leaked"
                    );
                }
            });
        }
        self.scrub_rpc_state(shard, validator_ids);
        let Drained { queued, swap } = self.seats.torn_down(shard);
        info!(shard = ?shard, "Shard left and torn down");
        if let Some((mut done, replaced)) = swap {
            for joiner in queued.into_iter().flatten() {
                if !done
                    .vnodes
                    .iter()
                    .any(|v| v.validator_id == joiner.validator_id)
                {
                    done.vnodes.push(joiner);
                }
            }
            self.swap_rebuilt(*done, storage, replaced);
        } else {
            drop(storage);
            if let Some(vnodes) = queued {
                self.join(shard, &vnodes);
            }
        }
        self.resume_pending_reshape_prep();
    }

    /// Remove a departed shard's slots from the shared RPC state maps.
    /// Each slot is otherwise written only by the shard's own (now
    /// joined) thread, so a stale entry would persist forever — worst
    /// case a mempool slot frozen at `at_pending_limit: true` vetoing
    /// every RPC submission. A vnode still hosted elsewhere (relocation
    /// overlap) republishes its mempool slot on that shard's next tick.
    fn scrub_rpc_state(&self, shard: ShardId, validator_ids: &[u64]) {
        let shard_key = shard.inner();
        self.publishers.node_status.rcu(|current| {
            let mut updated = (**current).clone();
            updated.vnodes.retain(|v| v.shard != shard_key);
            Arc::new(updated)
        });
        self.publishers.sync_status.rcu(|current| {
            let mut updated = (**current).clone();
            updated.shards.remove(&shard_key);
            Arc::new(updated)
        });
        self.publishers.mempool.rcu(|current| {
            let mut updated = (**current).clone();
            for id in validator_ids {
                updated.vnodes.remove(id);
            }
            Arc::new(updated)
        });
    }

    /// One [`VnodeConfig`] per seat-holding member of `shard`'s committee
    /// whose signing key this host holds — the local validators a seat or
    /// reconciled join attaches. Reads the seatable view, so a local split
    /// observer riding the committee is never attached as a signer
    /// alongside co-hosted real members.
    pub(super) fn local_committee_vnodes(
        &self,
        topology_snapshot: &TopologySnapshot,
        shard: ShardId,
    ) -> Vec<VnodeConfig> {
        seat_validators(topology_snapshot, shard, |validator| {
            self.vnode_keys.contains_key(&validator)
        })
        .into_iter()
        .filter_map(|validator| {
            self.vnode_keys.get(&validator).map(|signer| VnodeConfig {
                validator_id: validator,
                local_shard: shard,
                signer: Arc::clone(signer),
            })
        })
        .collect()
    }

    /// The vnode configs for every local validator [`placed_validators`]
    /// places on `shard`.
    fn placed_vnodes(&self, schedule: &TopologySchedule, shard: ShardId) -> Vec<VnodeConfig> {
        let placed = placed_validators(shard, schedule, |validator| {
            self.vnode_keys.contains_key(&validator)
        });
        self.vnodes(shard, &placed)
    }

    /// The vnode configs seating each of `validators` whose key this host
    /// holds on `shard`.
    fn vnodes(&self, shard: ShardId, validators: &[ValidatorId]) -> Vec<VnodeConfig> {
        validators
            .iter()
            .filter_map(|&validator| {
                self.vnode_keys.get(&validator).map(|signer| VnodeConfig {
                    validator_id: validator,
                    local_shard: shard,
                    signer: Arc::clone(signer),
                })
            })
            .collect()
    }

    /// How this host builds every replica it runs at runtime.
    fn replica_config(&self) -> ReplicaConfig {
        ReplicaConfig {
            verifier: Arc::new(BlsVerifier),
            derivation: self.process.derivation(),
            code: self.process.code(),
            beacon_network: self.beacon_network.clone(),
            beacon_config_hash: self.beacon_config_hash,
            shard_config: self.shard_config.clone(),
            mempool_config: self.mempool_config.clone(),
            provision_config: self.provision_config,
        }
    }
}

/// A running loop's shard, the validators attached to it and attaching,
/// and whether the seating plan may seat more on it.
type RunningSeats = (ShardId, Vec<ValidatorId>, Vec<ValidatorId>, bool);

/// The `running` loops as the seating plan reads them, over the `storages`
/// the supervisor holds.
fn hosted_views(
    running: Vec<RunningSeats>,
    storages: &BTreeMap<ShardId, Arc<RocksDbShardStorage>>,
) -> Vec<HostedView<'_, RocksDbShardStorage>> {
    running
        .into_iter()
        .map(|(shard, attached, attaching, seatable)| HostedView {
            shard,
            store: storages.get(&shard).map(AsRef::as_ref),
            attached,
            attaching,
            seatable,
        })
        .collect()
}

/// How long a swap waits for the replaced store's last handle to drop
/// before removing its directory regardless — the teardown's own leak
/// probe waits as long before warning.
const STORE_RELEASE_GRACE: Duration = Duration::from_secs(5);

/// Where a rebuild stages the store that replaces the one at `dir`:
/// beside it, so the swap is a rename within one filesystem.
fn staging_dir(dir: &Path) -> PathBuf {
    let mut staging = dir.as_os_str().to_owned();
    staging.push(".rebuild");
    PathBuf::from(staging)
}

/// Block until the replaced store's last handle drops — a serving
/// request or GC pass that outlived the teardown — or the grace runs
/// out.
fn await_release(store: Option<Weak<RocksDbShardStorage>>) {
    let Some(store) = store else {
        return;
    };
    let deadline = Instant::now() + STORE_RELEASE_GRACE;
    while store.strong_count() > 0 {
        if Instant::now() >= deadline {
            warn!("Replaced store still held at its swap; removing its directory regardless");
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
