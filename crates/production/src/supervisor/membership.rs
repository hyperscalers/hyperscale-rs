//! The supervisor's membership half: bring shards up and tear them down
//! against the committed beacon placement.
//!
//! A join opens storage off the loop, snap-syncs a fresh store against the
//! beacon-attested anchor (parking until this host's topology carries one,
//! unless the shard's chain runs from network genesis), and seats the
//! shard's vnodes on a new pinned thread; a leave refcounts memberships down and tears the thread, maps,
//! and storage down at zero. The reconcile pair is the committed-state
//! backstop: [`ShardSupervisor::reconcile_joins`] brings up any shard a
//! local validator holds a consensus seat in that a lost delta never
//! joined, and [`ShardSupervisor::reconcile_teardown`] retires a shard
//! once no local validator holds a committee or routing role in it. The
//! two read different committee views on purpose: joining asks "must this
//! host run consensus" (the seatable view, observer riders excluded);
//! teardown asks "does this host hold any window role" (full membership,
//! riders included).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_node::host::{attach_shard, detach_shard};
use hyperscale_node::startup::holds_window_role;
use hyperscale_node::{
    SeatConfig, SeatVnodeGroup, VnodeInit, VnodeSeat, installed_network_genesis_block,
    network_genesis_block, seat_vnode_group,
};
use hyperscale_storage::{RecoveredState, ShardChainReader, SubstateStore, holds_state};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{
    Block, BlockHeight, RoutingCommittees, ShardId, TopologySnapshot, ValidatorId,
};
use tokio::task::spawn_blocking;
use tokio::time::sleep;
use tracing::{info, warn};

use super::{ShardSupervisor, ShardThread, SupervisorEvent};
use crate::bootstrap::bootstrap_shard_state;
use crate::runner::{ShardChannels, ShardControl, VnodeConfig, consensus_clock, spawn_shard_loop};

/// A finished snap-sync bootstrap, ready for the supervisor to seat:
/// the imported storage verified against the attested anchor, plus the
/// recovered state the shard's state machines boot from.
pub struct CompletedBootstrap {
    shard: ShardId,
    vnodes: Vec<VnodeConfig>,
    storage: Arc<RocksDbShardStorage>,
    recovered: RecoveredState,
}

/// A running shard's rebuild at its attested anchor.
pub enum Rebuild {
    /// The staging store is syncing while the old loop keeps running.
    Staging,
    /// The staging store verified; the old loop is tearing down, and
    /// these vnodes seat on the staging store once it is renamed into
    /// the shard's directory.
    Swapping(Box<CompletedBootstrap>),
}

impl ShardSupervisor {
    /// Bring up `shard`: open its storage off this loop, then continue
    /// in [`Self::on_opened`] — seat directly for a retained store or a
    /// genesis replay, snap-sync against the beacon-attested anchor
    /// first, or park until the anchor reaches this host. A join for a
    /// shard still tearing down queues and replays once the teardown
    /// finishes; one for a shard already running seats into its loop,
    /// and one for a shard parked on its anchor joins the parked vnodes.
    pub(super) fn join(&mut self, shard: ShardId, vnodes: &[VnodeConfig]) {
        if self.bootstrapping.contains_key(&shard) {
            warn!(shard = ?shard, "Join rejected: shard still bootstrapping");
            return;
        }
        if vnodes.is_empty() || vnodes.iter().any(|v| v.local_shard != shard) {
            warn!(shard = ?shard, "Join rejected: vnodes must be non-empty and target the shard");
            return;
        }
        if self.draining.contains(&shard) {
            info!(shard = ?shard, "Join queued behind the shard's in-flight teardown");
            if self.pending_joins.insert(shard, vnodes.to_vec()).is_some() {
                warn!(shard = ?shard, "Replaced an earlier queued join for the shard");
            }
            return;
        }

        // A reshape duty owns seating this shard — a merge's keepers
        // reforming the parent, or a split's children, surfaced as an ordinary
        // join when the reshape executes. The orchestrator seats them from the
        // prepared store (which carries the reshape's terminal/merged state),
        // so the placement-delta join is a no-op here. The four conditions span
        // the duty's whole lifetime so the join never opens a `RocksDB`
        // directory the duty is using — `RocksDB`'s exclusive lock fails the
        // second opener outright, so an overlap strands a co-hosted committee
        // member's seat. `is_seating` reads the orchestrator's post-discovery
        // state; `reshape_owns` reads the committed projection, covering the
        // window before discovery runs and while the cohort is still published;
        // `reshape_stores` covers the late window after the beacon marks the
        // successor live (clearing the cohort, so `reshape_owns` lapses) while
        // the duty still holds the opened store between its open and seat; and
        // `pending_reshape_prep` covers a prep parked behind an earlier open.
        if self.reshape.is_seating(shard)
            || self.reshape_owns(shard)
            || self.reshape_stores.contains_key(&shard)
            || self.pending_reshape_prep.contains_key(&shard)
        {
            info!(shard = ?shard, "Join superseded by an active reshape duty; the orchestrator seats it");
            return;
        }
        if self.shards.contains_key(&shard) {
            self.seat_on_running(shard, vnodes);
            return;
        }
        if let Some(parked) = self.awaiting_anchor.get_mut(&shard) {
            for vnode in vnodes {
                if !parked.iter().any(|v| v.validator_id == vnode.validator_id) {
                    parked.push(vnode.clone());
                }
            }
            info!(shard = ?shard, "Join parked with the shard's others awaiting its anchor");
            return;
        }

        // The RocksDB open (and a previously-used store's recovery
        // read) can stall on disk; run it off the loop and continue in
        // `on_opened`. The `bootstrapping` entry blocks double joins
        // and lets a `Leave` during the open release memberships.
        self.bootstrapping
            .insert(shard, vnodes.iter().map(|v| v.validator_id).collect());
        let factory = Arc::clone(&self.storage_factory);
        let dir = (self.storage_dir)(shard);
        let engine_bootstrap = self.engine_bootstrap.clone();
        let events = self.events_tx.clone();
        let vnodes = vnodes.to_vec();
        self.tokio_handle.spawn_blocking(move || {
            let outcome = factory(&dir, shard).and_then(|storage| {
                // A clone of a split parent the reshape never adopted holds
                // nothing of this shard's chain, and a child span an observer
                // imported and never adopted holds state under no chain, which
                // the snap-sync import refuses to write over: wipe either, and
                // join from nothing.
                let unadopted = storage.holds_foreign_chain(shard)
                    || (storage.is_fresh()
                        && holds_state(storage.jmt_height(), storage.state_root()));
                if !unadopted {
                    return Ok(storage);
                }
                info!(shard = ?shard, "Join wiping a reshape store its duty never adopted");
                drop(storage);
                std::fs::remove_dir_all(&dir).map_err(|e| format!("unadopted clone wipe: {e}"))?;
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
    ///   `awaiting_anchor`, retried by [`Self::reconcile_joins`] once the
    ///   anchor arrives.
    pub(super) fn on_opened(
        &mut self,
        shard: ShardId,
        mut vnodes: Vec<VnodeConfig>,
        outcome: Result<(Arc<RocksDbShardStorage>, RecoveredState), String>,
    ) {
        let Some(pending) = self.bootstrapping.get(&shard).cloned() else {
            info!(shard = ?shard, "Storage opened for an abandoned join; dropped");
            return;
        };
        let (storage, recovered) = match outcome {
            Ok(opened) => opened,
            Err(error) => {
                self.bootstrapping.remove(&shard);
                warn!(shard = ?shard, error, "Join rejected: storage open failed");
                return;
            }
        };
        // A reshape duty has since claimed this shard — the join slipped past
        // the `reshape_owns` suppression against a stale snapshot and opened the
        // store anyway. Drop it (releasing the `RocksDB` lock) and let the duty
        // seat the shard from its terminal/merged store; any prep held behind
        // this open can now run.
        if self.reshape_owns(shard) {
            self.bootstrapping.remove(&shard);
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
            self.tokio_handle.spawn(async move {
                let done = match bootstrap_shard_state(
                    process.network(),
                    process.topology_snapshot(),
                    &storage,
                    shard,
                    None,
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
        self.bootstrapping.remove(&shard);
        if !fresh_store && recovered.committed_height == BlockHeight::GENESIS {
            let genesis = installed_network_genesis_block(shard, storage.state_root());
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
            self.awaiting_anchor.insert(shard, vnodes);
            return;
        }
        let genesis = network_genesis_block(
            storage.as_ref(),
            shard,
            &topology_snapshot,
            &self.engine_bootstrap.config,
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
    /// the bootstrapping entry on failure (so a later placement delta
    /// can retry the join), drop the outcome when every pending vnode
    /// left during the bootstrap. Runs on the runner's loop via the
    /// completion channel — never on the bootstrap task.
    pub(super) fn finish_join(&mut self, done: Result<CompletedBootstrap, ShardId>) {
        let shard = match &done {
            Ok(done) => done.shard,
            Err(shard) => *shard,
        };
        let Some(pending) = self.bootstrapping.remove(&shard) else {
            info!(shard = ?shard, "Bootstrap finished for an abandoned join; dropped");
            return;
        };
        let Ok(mut done) = done else {
            // Failure already logged by the bootstrap task.
            return;
        };
        if self.shards.contains_key(&shard) {
            warn!(shard = ?shard, "Bootstrap completed for an already-hosted shard; dropped");
            return;
        }
        done.vnodes
            .retain(|vnode| pending.contains(&vnode.validator_id));
        self.seat_shard(shard, &done.vnodes, done.storage, &done.recovered);
    }

    /// Wire a shard's vnodes into the process maps and spawn its pinned
    /// thread, booting the state machines from `recovered`.
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
    pub(super) fn seat_shard_with_genesis(
        &mut self,
        shard: ShardId,
        vnodes: &[VnodeConfig],
        storage: Arc<RocksDbShardStorage>,
        recovered: &RecoveredState,
        genesis: Option<&Block>,
    ) {
        let inits = self.build_vnode_inits(shard, vnodes, recovered);
        let seated = inits.len();
        let (channels, callback_tx) = ShardChannels::new();
        let mut shard_loop = attach_shard(
            &self.process,
            &self.node_config,
            inits,
            (*storage).clone(),
            callback_tx,
        );
        shard_loop.set_time(consensus_clock(self.genesis_offset_ms));
        // The genesis commit — or, for a non-genesis seat, the
        // committed-state resume — arms the pacemaker; capture its timer
        // ops so the spawned loop arms them as its initial ops rather than
        // dropping them.
        let initial_timer_ops = match genesis {
            Some(genesis) => shard_loop.install_genesis(genesis),
            None => shard_loop.resume_committed(recovered),
        };

        self.storages
            .lock()
            .expect("storages lock")
            .insert(shard, storage);

        let shutdown_tx = channels.shutdown_tx.clone();
        let control_tx = channels.control_tx.clone();
        let validator_ids = vnodes.iter().map(|v| v.validator_id.inner()).collect();
        let cfg = self.loop_config(channels, initial_timer_ops);
        let join = spawn_shard_loop(shard_loop, cfg);
        self.shards.insert(
            shard,
            ShardThread {
                join,
                shutdown_tx,
                control_tx,
                queued: Vec::new(),
                validator_ids,
            },
        );
        // A seated validator now drives its beacon from this shard's thread,
        // so retire its pool follower if it had one (it drained here from a
        // prior shard, or started pooled and was just drawn into a committee).
        for cfg in vnodes {
            self.unfollow_in_pool(cfg.validator_id);
        }
        info!(shard = ?shard, vnodes = seated, "Shard joined at runtime");
    }

    /// Seat `vnodes` on `shard`'s running loop, or rebuild the loop first
    /// when a fork recovery would seat one of them above its attested
    /// frontier. A shard already rebuilding seats every placed validator
    /// when its swap lands.
    fn seat_on_running(&mut self, shard: ShardId, vnodes: &[VnodeConfig]) {
        if self.rebuilding.contains_key(&shard) {
            return;
        }
        if self.rebuild_due(shard, vnodes) {
            self.rebuild(shard, vnodes);
        } else {
            self.seat_into_running(shard, vnodes);
        }
    }

    /// Whether seating `vnodes` on `shard`'s running loop would restore a
    /// fresh member above a fork recovery's attested frontier: the loop's
    /// store committed past it on a branch the fresh committee must not
    /// extend, and a store cannot un-commit.
    fn rebuild_due(&self, shard: ShardId, vnodes: &[VnodeConfig]) -> bool {
        let Some(frontier) = self
            .process
            .topology_snapshot()
            .load()
            .fork_recovery_frontier(shard)
        else {
            return false;
        };
        let Some(entry) = self.shards.get(&shard) else {
            return false;
        };
        let unseated = vnodes
            .iter()
            .any(|vnode| !entry.validator_ids.contains(&vnode.validator_id.inner()));
        unseated
            && self
                .storages
                .lock()
                .expect("storages lock")
                .get(&shard)
                .is_some_and(|storage| storage.committed_height() > frontier)
    }

    /// Rebuild `shard` at its attested anchor, make before break: a
    /// staging store beside the shard's directory snap-syncs while the old
    /// loop keeps running and serving, reading the old store first and
    /// peers for what it no longer holds. [`Self::on_rebuilt`] swaps it
    /// in.
    fn rebuild(&mut self, shard: ShardId, vnodes: &[VnodeConfig]) {
        let old = self
            .storages
            .lock()
            .expect("storages lock")
            .get(&shard)
            .cloned();
        let Some(old) = old else {
            return;
        };
        self.rebuilding.insert(shard, Rebuild::Staging);
        info!(shard = ?shard, "Rebuilding a forked shard's store at its attested anchor");
        let staging_dir = staging_dir(&(self.storage_dir)(shard));
        let factory = Arc::clone(&self.storage_factory);
        let engine_bootstrap = self.engine_bootstrap.clone();
        let process = Arc::clone(&self.process);
        let events = self.events_tx.clone();
        let vnodes = vnodes.to_vec();
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
            let done = staged.map_err(|error| {
                warn!(shard = ?shard, error, "Shard rebuild failed; its loop keeps running");
                shard
            });
            // Send failure means the runner is shutting down; the rebuild
            // dies with it.
            let _ = events.send(SupervisorEvent::Rebuilt(done));
        });
    }

    /// Settle a rebuild's staging: tear the old loop down, and seat on the
    /// staging store every local validator placed on the shard, the
    /// joiner that triggered the rebuild included, once
    /// [`Self::on_torn_down`] has renamed it into place. A validator the
    /// old loop carried and the shard no longer places follows the beacon
    /// in the pool, as any drained validator does.
    pub(super) fn on_rebuilt(&mut self, done: Result<CompletedBootstrap, ShardId>) {
        let mut done = match done {
            Ok(done) => done,
            Err(shard) => {
                self.rebuilding.remove(&shard);
                return;
            }
        };
        let shard = done.shard;
        if !self.shards.contains_key(&shard) {
            // Torn down while the staging store synced: nothing to swap.
            self.rebuilding.remove(&shard);
            let staging_dir = staging_dir(&(self.storage_dir)(shard));
            self.tokio_handle.spawn_blocking(move || {
                drop(done);
                if let Err(error) = std::fs::remove_dir_all(&staging_dir) {
                    warn!(shard = ?shard, %error, "Abandoned staging store left on disk");
                }
            });
            return;
        }
        let snapshot = self.process.topology_snapshot().load_full();
        let mut vnodes = self.local_committee_vnodes(&snapshot, shard);
        for joiner in std::mem::take(&mut done.vnodes) {
            if !vnodes.iter().any(|v| v.validator_id == joiner.validator_id) {
                vnodes.push(joiner);
            }
        }
        done.vnodes = vnodes;
        self.rebuilding
            .insert(shard, Rebuild::Swapping(Box::new(done)));
        self.tear_down(shard);
    }

    /// Replace `shard`'s store with its rebuilt one and seat it: once the
    /// old store's last handle is gone, remove its directory, rename the
    /// staging directory into its place, and reopen it there, settling
    /// through [`Self::finish_join`] as a snap-synced join does.
    fn swap_rebuilt(&mut self, done: CompletedBootstrap, old: Option<Weak<RocksDbShardStorage>>) {
        let CompletedBootstrap {
            shard,
            vnodes,
            storage,
            recovered,
        } = done;
        self.bootstrapping
            .insert(shard, vnodes.iter().map(|v| v.validator_id).collect());
        let dir = (self.storage_dir)(shard);
        let factory = Arc::clone(&self.storage_factory);
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            drop(storage);
            let outcome = (|| -> Result<Arc<RocksDbShardStorage>, String> {
                await_release(old);
                if dir.exists() {
                    std::fs::remove_dir_all(&dir)
                        .map_err(|e| format!("replaced store removal: {e}"))?;
                }
                std::fs::rename(staging_dir(&dir), &dir)
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

    /// Queue each of `vnodes` the running loop of `shard` does not already
    /// carry or queue: a validator drawn onto a shard this host serves
    /// joins the loop rather than a thread of its own. The loop admits it
    /// once its store is at rest and reports it back as
    /// [`SupervisorEvent::Seated`].
    fn seat_into_running(&mut self, shard: ShardId, vnodes: &[VnodeConfig]) {
        let config = self.seat_config();
        let Some(entry) = self.shards.get_mut(&shard) else {
            return;
        };
        for vnode in vnodes {
            let id = vnode.validator_id.inner();
            if entry.validator_ids.contains(&id) || entry.queued.contains(&id) {
                continue;
            }
            let seat = VnodeSeat {
                config: config.clone(),
                validator: vnode.validator_id,
                signer: Arc::clone(&vnode.signer),
            };
            if entry
                .control_tx
                .send(ShardControl::Seat(Box::new(seat)))
                .is_ok()
            {
                entry.queued.push(id);
                info!(shard = ?shard, validator = id, "Seat queued on a running shard");
            }
        }
    }

    /// A running loop admitted a queued seat: count the validator among
    /// the shard's, and retire its pool follower, since it drives its
    /// beacon from this shard now.
    pub(super) fn on_seated(&mut self, shard: ShardId, validator: ValidatorId) {
        let Some(entry) = self.shards.get_mut(&shard) else {
            return;
        };
        let id = validator.inner();
        entry.queued.retain(|&queued| queued != id);
        if !entry.validator_ids.contains(&id) {
            entry.validator_ids.push(id);
        }
        self.unfollow_in_pool(validator);
        info!(shard = ?shard, validator = id, "Seat admitted on a running shard");
    }

    /// Release `validator`'s membership in `shard`; tear the shard down
    /// when it was the last. A leave that lands while the shard's join is
    /// still bootstrapping, or parked on its anchor, releases that pending
    /// membership instead, abandoning the join when the last one goes.
    pub(super) fn leave(&mut self, shard: ShardId, validator: ValidatorId) {
        if let Some(pending) = self.bootstrapping.get_mut(&shard) {
            pending.remove(&validator);
            if pending.is_empty() {
                self.bootstrapping.remove(&shard);
                info!(shard = ?shard, "Last pending vnode left during bootstrap; join abandoned");
            } else {
                info!(
                    shard = ?shard,
                    remaining = pending.len(),
                    "Vnode left during bootstrap; join continues for remaining vnodes"
                );
            }
            return;
        }
        if let Some(parked) = self.awaiting_anchor.get_mut(&shard) {
            parked.retain(|vnode| vnode.validator_id != validator);
            if parked.is_empty() {
                self.awaiting_anchor.remove(&shard);
                info!(shard = ?shard, "Last parked vnode left; join awaiting the anchor abandoned");
            }
            return;
        }
        let Some(entry) = self.shards.get_mut(&shard) else {
            warn!(shard = ?shard, "Leave rejected: shard not hosted");
            return;
        };
        let id = validator.inner();
        if !entry.validator_ids.contains(&id) {
            warn!(shard = ?shard, validator = id, "Leave rejected: validator not seated on the shard");
            return;
        }
        if entry.validator_ids.len() == 1 {
            self.tear_down(shard);
            return;
        }
        if entry
            .control_tx
            .send(ShardControl::Remove(validator))
            .is_err()
        {
            return;
        }
        entry.validator_ids.retain(|&kept| kept != id);
        info!(
            shard = ?shard,
            validator = id,
            remaining = entry.validator_ids.len(),
            "Vnode left; shard stays up for remaining local vnodes"
        );
        if !self.validator_on_any_shard(validator) {
            self.follow_in_pool(validator);
        }
    }

    /// Tear a hosted shard's thread down and unwire it off the loop:
    /// signal shutdown, drop the entry, and join the thread off-loop,
    /// finishing the unwire in [`Self::on_torn_down`]. Shared by the
    /// explicit per-vnode [`Self::leave`] at zero count and the
    /// reshape-tick routable-expiry reconcile.
    fn tear_down(&mut self, shard: ShardId) {
        let Some(entry) = self.shards.remove(&shard) else {
            return;
        };
        let _ = entry.shutdown_tx.send(());
        // The thread join waits out an in-flight shard step; run it off
        // the loop and finish the unwire in `on_torn_down`.
        self.draining.insert(shard);
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            if entry.join.join().is_err() {
                warn!(shard = ?shard, "Shard thread panicked before teardown");
            }
            // Send failure means the runner is shutting down; the
            // teardown finishes with it.
            let _ = events.send(SupervisorEvent::TornDown {
                shard,
                validator_ids: entry.validator_ids,
            });
        });
    }

    /// Reconcile hosted shards against the committed routing window: tear
    /// down a shard once no local validator holds a role in its active
    /// committee and none sits in its routing committee (no serve
    /// obligation — the shard aged out of the routable window, or the
    /// validator rotated off a still-live shard).
    ///
    /// The active-committee guard keeps a shard up through its current
    /// window even after a lookahead delta moved the validator on in
    /// routing; the routing guard keeps a dissolved shard served for as
    /// long as a fetch can still resolve this host among its peers, so a
    /// merge keeper that does not co-host a merging child can still
    /// snap-sync it. Run on the reshape tick, binding serving and routing
    /// to one committed lifetime in place of a fixed drain grace.
    pub(crate) fn reconcile_teardown(&mut self) {
        let topology_snapshot = self.process.topology_snapshot().load();
        let routing = self.process.network().routing_committees();
        let host_ids: HashSet<ValidatorId> = self.vnode_keys.keys().copied().collect();
        let expired: Vec<ShardId> = self
            .shards
            .keys()
            .copied()
            .filter(|&shard| shard_retired(shard, &topology_snapshot, &routing, &host_ids))
            .collect();
        for shard in expired {
            info!(
                shard = ?shard,
                "Shard aged out of the routable window; tearing down"
            );
            self.tear_down(shard);
        }
        // A shard that stays up releases, by the same rule applied per
        // validator, each vnode that no longer holds a role in it, while
        // another seat keeps the loop running.
        let mut released: Vec<ValidatorId> = Vec::new();
        for (&shard, entry) in &mut self.shards {
            for id in entry.validator_ids.clone() {
                let validator = ValidatorId::new(id);
                let alone = HashSet::from([validator]);
                if entry.validator_ids.len() > 1
                    && shard_retired(shard, &topology_snapshot, &routing, &alone)
                    && entry
                        .control_tx
                        .send(ShardControl::Remove(validator))
                        .is_ok()
                {
                    entry.validator_ids.retain(|&kept| kept != id);
                    released.push(validator);
                    info!(shard = ?shard, validator = id, "Vnode left a running shard");
                }
            }
        }
        for validator in released {
            if !self.validator_on_any_shard(validator) {
                self.follow_in_pool(validator);
            }
        }
    }

    /// Reconcile hosted shards against the committed committee assignment: bring
    /// up any shard a local validator holds a consensus seat in that this host is
    /// not already hosting, bootstrapping, draining, seating from a reshape
    /// duty, or holding queued behind a drain. A split-observer ride is not a
    /// seat — the observer's physical work is its child store, driven by the
    /// reshape orchestrator, never a consensus vnode on the splitting parent.
    ///
    /// The membership-up mirror of [`Self::reconcile_teardown`]. The placement
    /// delta still drives a join immediately (it arrives an epoch ahead, so the
    /// bootstrap completes before the window opens); this is the committed-state
    /// backstop for a delta that was never seen — a join that raced a teardown
    /// and lost its queued replay, or work missed across a restart — so a
    /// dropped delta cannot strand the host off a shard it must run. Idempotent:
    /// the guards skip every shard already accounted for, and [`Self::join`]
    /// rejects a double bring-up regardless. A join parked on its shard's
    /// anchor is retried here once this host's topology carries it. Run on
    /// the reshape tick.
    pub(crate) fn reconcile_joins(&mut self) {
        let topology_snapshot = self.process.topology_snapshot().load_full();
        let anchored: Vec<ShardId> = self
            .awaiting_anchor
            .keys()
            .copied()
            .filter(|&shard| {
                topology_snapshot.boundary(shard).is_some()
                    || topology_snapshot.genesis_unanchored(shard)
            })
            .collect();
        for shard in anchored {
            if let Some(vnodes) = self.awaiting_anchor.remove(&shard) {
                info!(shard = ?shard, "Retrying a join parked on its anchor");
                self.join(shard, &vnodes);
            }
        }
        let host_ids: HashSet<ValidatorId> = self.vnode_keys.keys().copied().collect();
        // A running shard seats a local member it does not yet carry.
        let running: Vec<ShardId> = self
            .shards
            .keys()
            .copied()
            .filter(|&shard| !self.reshape.is_seating(shard))
            .collect();
        for shard in running {
            let vnodes = self.local_committee_vnodes(&topology_snapshot, shard);
            self.seat_on_running(shard, &vnodes);
        }
        let needed: Vec<ShardId> = topology_snapshot
            .shard_trie()
            .leaves()
            .filter(|&shard| {
                host_holds_seat(shard, &topology_snapshot, &host_ids)
                    && !self.shards.contains_key(&shard)
                    && !self.bootstrapping.contains_key(&shard)
                    && !self.draining.contains(&shard)
                    && !self.pending_joins.contains_key(&shard)
                    && !self.awaiting_anchor.contains_key(&shard)
                    && !self.reshape.is_seating(shard)
                    && !self.reshape_stores.contains_key(&shard)
            })
            .collect();
        for shard in needed {
            let vnodes = self.local_committee_vnodes(&topology_snapshot, shard);
            info!(shard = ?shard, "Reconciling a missed committee join from the committed view");
            self.join(shard, &vnodes);
        }
    }

    /// Finish a teardown whose thread joined: unwire the process maps,
    /// drop the storage handle, scrub the RPC slots, and replay any
    /// join that queued behind the drain.
    pub(super) fn on_torn_down(&mut self, shard: ShardId, validator_ids: &[u64]) {
        detach_shard(&self.process, shard);
        let storage = self.storages.lock().expect("storages lock").remove(&shard);
        let released = storage.as_ref().map(Arc::downgrade);
        if let Some(storage) = storage {
            // A store handle that outlives its teardown holds the RocksDB
            // directory lock, and every later re-seat of this host onto the
            // shard fails its storage open until the process restarts. That
            // failure is silent at the leak site and surfaces minutes or
            // days later as a join-retry loop, so probe for it: transient
            // holders (an in-flight GC pass, a serving request) drain in
            // well under the grace.
            let probe = Arc::downgrade(&storage);
            drop(storage);
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
        self.draining.remove(&shard);
        info!(shard = ?shard, "Shard left and torn down");
        // A departed validator that runs no other shard would go dark — no
        // vnode to fold the beacon and raise its own re-seat trigger. Keep
        // it following in the pool instead; the host's beacon storage stays
        // warm for the eventual re-seat. A relocation that already seated
        // the destination leaves the validator on that shard, so it is not
        // pooled; a race that pools it is undone when the seat lands.
        for &id in validator_ids {
            let validator = ValidatorId::new(id);
            if !self.validator_on_any_shard(validator) {
                self.follow_in_pool(validator);
            }
        }
        if let Some(Rebuild::Swapping(done)) = self.rebuilding.remove(&shard) {
            self.swap_rebuilt(*done, released);
        }
        if let Some(vnodes) = self.pending_joins.remove(&shard) {
            self.join(shard, &vnodes);
        }
    }

    /// Remove a departed shard's slots from the shared RPC state maps.
    /// Each slot is otherwise written only by the shard's own (now
    /// joined) thread, so a stale entry would persist forever — worst
    /// case a mempool slot frozen at `at_pending_limit: true` vetoing
    /// every RPC submission. A vnode still hosted elsewhere (relocation
    /// overlap) republishes its mempool slot on that shard's next tick.
    fn scrub_rpc_state(&self, shard: ShardId, validator_ids: &[u64]) {
        let shard_key = shard.inner();
        if let Some(ref rpc_status) = self.publishers.node_status {
            rpc_status.rcu(|current| {
                let mut updated = (**current).clone();
                updated.vnodes.retain(|v| v.shard != shard_key);
                Arc::new(updated)
            });
        }
        if let Some(ref sync_status) = self.publishers.sync_status {
            sync_status.rcu(|current| {
                let mut updated = (**current).clone();
                updated.shards.remove(&shard_key);
                Arc::new(updated)
            });
        }
        if let Some(ref mempool_snapshot) = self.publishers.mempool {
            mempool_snapshot.rcu(|current| {
                let mut updated = (**current).clone();
                for id in validator_ids {
                    updated.vnodes.remove(id);
                }
                Arc::new(updated)
            });
        }
    }

    /// One [`VnodeConfig`] per seat-holding member of `shard`'s committee
    /// whose signing key this host holds — the local vnodes a seat or
    /// reconciled join brings up. Reads the seatable view, so a local
    /// split observer riding the committee is never built into a vnode
    /// alongside co-hosted real members.
    pub(super) fn local_committee_vnodes(
        &self,
        topology_snapshot: &TopologySnapshot,
        shard: ShardId,
    ) -> Vec<VnodeConfig> {
        topology_snapshot
            .seatable_committee_for_shard(shard)
            .filter_map(|validator| {
                self.vnode_keys.get(&validator).map(|signer| VnodeConfig {
                    validator_id: validator,
                    local_shard: shard,
                    signer: Arc::clone(signer),
                })
            })
            .collect()
    }

    /// Build one `VnodeInit` per joining vnode via [`seat_vnode_group`],
    /// resuming from the host's committed beacon chain and booting from
    /// `recovered`.
    fn build_vnode_inits(
        &self,
        shard: ShardId,
        vnodes: &[VnodeConfig],
        recovered: &RecoveredState,
    ) -> Vec<VnodeInit> {
        seat_vnode_group(SeatVnodeGroup {
            config: self.seat_config(),
            beacon_storage: self.process.beacon_storage().as_ref(),
            now: consensus_clock(self.genesis_offset_ms),
            shard,
            recovered,
            vnodes: vnodes
                .iter()
                .map(|cfg| (cfg.validator_id, Arc::clone(&cfg.signer)))
                .collect(),
        })
    }

    /// How this host builds every vnode it seats at runtime.
    fn seat_config(&self) -> SeatConfig {
        SeatConfig {
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

/// Whether a hosted shard has aged out of this host's serving duty: no
/// local validator holds any role in its active committee and none sits
/// in its routing committee (no serve obligation).
///
/// The active-committee guard keeps a shard up through its current window
/// even after a lookahead delta has moved the validator on in the routing
/// view; the routing guard keeps a dissolved shard served for as long as
/// a fetch can still resolve this host among its peers. Both false means
/// the shard is still wanted — it retires only when neither holds, so
/// serving and routing share the one committed lifetime.
fn shard_retired(
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    routing: &RoutingCommittees,
    host_ids: &HashSet<ValidatorId>,
) -> bool {
    // A reshape predecessor mid-handoff stays up even once it ages out of the
    // routable window: under make-before-break its committee stays seated,
    // serving its terminal, until the successors are live, so they can seed and
    // finalize against it.
    !holds_window_role(shard, topology_snapshot, routing, host_ids)
        && !topology_snapshot.reshape_handoff_pending(shard)
}

/// Whether a local validator holds a consensus seat in `shard`'s committed
/// committee — the join half's membership question, read from the seatable
/// view. A split observer riding the committee never reads as a seat: seating
/// it would emit a shard-joiner ready signal that classifies as the cohort's
/// `ReshapeReady` and could fire the split gate before its child store has
/// synced.
fn host_holds_seat(
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    host_ids: &HashSet<ValidatorId>,
) -> bool {
    topology_snapshot
        .seatable_committee_for_shard(shard)
        .any(|v| host_ids.contains(&v))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_node::startup::host_in_committee;
    use hyperscale_types::{
        NetworkDefinition, ReshapeSeat, RoutingCommittees, ShardId, Signer, TopologySnapshot,
        ValidatorId, ValidatorInfo, ValidatorSet,
    };

    use super::{host_holds_seat, shard_retired};

    const HOST: ValidatorId = ValidatorId::new(1);

    /// A head snapshot carrying `committees` as each shard's active
    /// membership — a complete sibling set so the trie is well-formed.
    fn head(committees: HashMap<ShardId, Vec<ValidatorId>>) -> TopologySnapshot {
        head_with_observers(committees, BTreeMap::new())
    }

    /// [`head`] with pending-split observer cohorts riding the committees.
    fn head_with_observers(
        committees: HashMap<ShardId, Vec<ValidatorId>>,
        observers: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    ) -> TopologySnapshot {
        let ids: BTreeSet<ValidatorId> = committees.values().flatten().copied().collect();
        let validators: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&validator_id| ValidatorInfo {
                validator_id,
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(validators),
            committees,
            HashMap::new(),
            BTreeMap::new(),
            HashMap::new(),
            observers
                .into_iter()
                .map(|(parent, cohort)| {
                    let seats = cohort
                        .into_iter()
                        .map(|(id, shard)| {
                            (
                                id,
                                ReshapeSeat {
                                    shard,
                                    ready: false,
                                },
                            )
                        })
                        .collect();
                    (parent, seats)
                })
                .collect(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        )
    }

    fn routing(entries: &[(ShardId, Vec<ValidatorId>)]) -> RoutingCommittees {
        entries.iter().cloned().collect()
    }

    /// A live shard the host rotated off — gone from both its active and
    /// its routing committee — retires.
    #[test]
    fn retires_a_shard_absent_from_active_and_routing() {
        let shard = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let others = vec![ValidatorId::new(2), ValidatorId::new(3)];
        let topology_snapshot = head(HashMap::from([
            (shard, others.clone()),
            (sibling, vec![ValidatorId::new(4)]),
        ]));
        let routing = routing(&[(shard, others)]);
        assert!(shard_retired(
            shard,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// A merge child gone from the head but retained in routing with the
    /// host among its terminal committee stays served — the keeper-fetch
    /// case the fix exists for.
    #[test]
    fn keeps_a_dissolved_shard_the_host_still_routes() {
        let child = ShardId::leaf(2, 2);
        let topology_snapshot = head(HashMap::from([
            (ShardId::leaf(1, 0), vec![ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![HOST]),
        ]));
        let routing = routing(&[(child, vec![HOST, ValidatorId::new(2)])]);
        assert!(!shard_retired(
            child,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// The host still sits in the active committee — kept even after the
    /// routing lookahead has moved it on, so the current window is served
    /// to its end.
    #[test]
    fn keeps_a_shard_with_an_active_consensus_role() {
        let shard = ShardId::leaf(1, 0);
        let topology_snapshot = head(HashMap::from([
            (shard, vec![HOST, ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![ValidatorId::new(4)]),
        ]));
        // The lookahead already moved the host off in routing.
        let routing = routing(&[(shard, vec![ValidatorId::new(2), ValidatorId::new(3)])]);
        assert!(!shard_retired(
            shard,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// A dissolved shard aged out of routing entirely retires — once its
    /// reshape handoff has completed. Here `leaf(2, 2)` merged into `leaf(1, 1)`,
    /// which is now live (advanced past genesis), so the predecessor is free.
    #[test]
    fn retires_a_shard_evicted_from_routing() {
        let child = ShardId::leaf(2, 2);
        let topology_snapshot = head(HashMap::from([
            (ShardId::leaf(1, 0), vec![ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![HOST]),
        ]))
        .with_advanced([ShardId::leaf(1, 1)].into());
        let routing = RoutingCommittees::new();
        assert!(shard_retired(
            child,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// A reshape predecessor mid-handoff is held up even once it has aged out of
    /// routing: its successors aren't live yet, so it keeps serving its terminal.
    #[test]
    fn holds_a_reshape_predecessor_until_its_successor_is_live() {
        let child = ShardId::leaf(2, 2);
        // `leaf(2, 2)` merged into `leaf(1, 1)`, which is seated but not yet live.
        let topology_snapshot = head(HashMap::from([
            (ShardId::leaf(1, 0), vec![ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![HOST]),
        ]));
        let routing = RoutingCommittees::new();
        assert!(!shard_retired(
            child,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// The join reconcile targets exactly the committed committees a local
    /// validator belongs to; without a pending split the two membership
    /// views agree.
    #[test]
    fn host_holds_seat_tracks_committed_committee_membership() {
        let mine = ShardId::leaf(1, 0);
        let theirs = ShardId::leaf(1, 1);
        let topology_snapshot = head(HashMap::from([
            (mine, vec![HOST, ValidatorId::new(2)]),
            (theirs, vec![ValidatorId::new(3)]),
        ]));
        let host_ids = HashSet::from([HOST]);
        assert!(host_holds_seat(mine, &topology_snapshot, &host_ids));
        assert!(!host_holds_seat(theirs, &topology_snapshot, &host_ids));
        assert!(host_in_committee(mine, &topology_snapshot, &host_ids));
        assert!(!host_in_committee(theirs, &topology_snapshot, &host_ids));
    }

    /// A split-observer ride is a committee role but not a consensus seat:
    /// the join reconcile must not bring the splitting parent up on a host
    /// whose only stake in it is the observer, while a co-hosted real
    /// member still reads as a seat.
    #[test]
    fn an_observer_ride_is_not_a_consensus_seat() {
        let parent = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let (child, _) = parent.children();
        let member = ValidatorId::new(2);
        let topology_snapshot = head_with_observers(
            HashMap::from([
                (parent, vec![member, ValidatorId::new(3), HOST]),
                (sibling, vec![ValidatorId::new(4)]),
            ]),
            BTreeMap::from([(parent, BTreeMap::from([(HOST, child)]))]),
        );

        let observer_only = HashSet::from([HOST]);
        assert!(!host_holds_seat(parent, &topology_snapshot, &observer_only));
        assert!(host_in_committee(
            parent,
            &topology_snapshot,
            &observer_only
        ));

        let co_hosting = HashSet::from([HOST, member]);
        assert!(host_holds_seat(parent, &topology_snapshot, &co_hosting));
    }

    /// The teardown half deliberately reads full membership: a hosted shard
    /// whose only local committee link is an observer ride stays up for the
    /// window even with no routing entry.
    #[test]
    fn keeps_a_shard_the_host_only_observes() {
        let parent = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let (child, _) = parent.children();
        let topology_snapshot = head_with_observers(
            HashMap::from([
                (parent, vec![ValidatorId::new(2), HOST]),
                (sibling, vec![ValidatorId::new(3)]),
            ]),
            BTreeMap::from([(parent, BTreeMap::from([(HOST, child)]))]),
        );
        let routing = RoutingCommittees::new();
        assert!(!shard_retired(
            parent,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }
}
