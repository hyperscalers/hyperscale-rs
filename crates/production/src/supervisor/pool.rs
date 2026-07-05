//! The supervisor's follower-pool half: the pinned thread lifecycle for a
//! host's shard-less, beacon-following vnodes.
//!
//! A validator that drains off its last shard keeps following the beacon in
//! the pool — it must fold placements to raise its own re-seat trigger — and
//! a seat retires its follower again. The pool is rebuilt, never mutated: a
//! membership change tears the thread down and spawns a fresh one over the
//! adjusted follower set, resuming cheaply from the host's warm beacon
//! storage.

use std::sync::Arc;

use crossbeam::channel::{Sender, unbounded};
use hyperscale_node::pool_loop::PoolLoop;
use hyperscale_node::{SeatFollower, VnodeInit, seat_follower};
use hyperscale_types::ValidatorId;
use tracing::{info, warn};

use super::ShardSupervisor;
use crate::runner::{PoolLoopConfig, ProdPoolLoop, consensus_clock, spawn_pool_loop};

/// The host's pinned pool thread plus the handle to stop it, and the
/// follower validators it currently drives — a membership change rebuilds
/// the pool with the adjusted set.
pub(super) struct PoolThread {
    join: std::thread::JoinHandle<()>,
    shutdown_tx: Sender<()>,
    /// Validators currently followed by the pool. A drain off the last
    /// shard adds one; a seat removes one; the pool tears down at zero.
    validators: Vec<ValidatorId>,
}

impl ShardSupervisor {
    /// Spawn the host's beacon-follower pool thread from a pre-built
    /// `PoolLoop` — the startup pooled host (a registered-but-unseated
    /// validator). A pool already running is left in place.
    pub(crate) fn install_pool(&mut self, pool: ProdPoolLoop) {
        if self.pool.is_some() {
            warn!("install_pool called while a pool thread already runs; ignored");
            return;
        }
        self.start_pool_thread(pool);
    }

    /// Spawn a pinned thread for `pool`, recording its handle and follower
    /// set. The thread drains a clone of the host's beacon channel; the
    /// host-level gossip handler pushes committed beacon blocks onto the
    /// paired sender.
    fn start_pool_thread(&mut self, pool: ProdPoolLoop) {
        let validators: Vec<ValidatorId> = pool.vnodes.iter().map(|v| v.validator_id).collect();
        let (shutdown_tx, shutdown_rx) = unbounded();
        let cfg = PoolLoopConfig {
            beacon_rx: self.beacon_event_rx.clone(),
            shutdown_rx,
            participation_tx: self.participation_tx.clone(),
            genesis_offset_ms: self.genesis_offset_ms,
        };
        let join = spawn_pool_loop(pool, cfg);
        self.pool = Some(PoolThread {
            join,
            shutdown_tx,
            validators,
        });
        // The thread is now draining the host's beacon channel; let the
        // host-level gossip handler route committed blocks to it.
        self.process.set_beacon_route_active(true);
    }

    /// Stop the pool thread if one runs, joining it.
    pub(super) fn teardown_pool(&mut self) {
        if let Some(pt) = self.pool.take() {
            // Stop routing before the drain ends so the channel can't back
            // up between the shutdown signal and the thread's exit.
            self.process.set_beacon_route_active(false);
            let _ = pt.shutdown_tx.send(());
            if pt.join.join().is_err() {
                warn!("Pool thread panicked before teardown");
            }
        }
    }

    /// Rebuild the pool thread to follow exactly `validators`: tear the
    /// current thread down, and — unless the set is now empty — build a
    /// fresh follower per validator from the host's warm beacon storage and
    /// spawn a new thread. Tearing down and rebuilding (rather than mutating
    /// a running thread) keeps the follower set a single owned value; a
    /// follower resumes cheaply from the warm storage tip.
    fn rebuild_pool(&mut self, validators: &[ValidatorId]) {
        self.teardown_pool();
        if validators.is_empty() {
            return;
        }
        let vnodes: Vec<_> = validators
            .iter()
            .filter_map(|&validator| self.build_follower(validator))
            .map(VnodeInit::into_vnode)
            .collect();
        if vnodes.is_empty() {
            return;
        }
        let pool = PoolLoop::new(Arc::clone(&self.process), vnodes);
        self.start_pool_thread(pool);
    }

    /// Build one shard-less follower for `validator` from the host's warm
    /// beacon storage. `None` when the validator has no local signing key
    /// (it isn't ours to follow for).
    fn build_follower(&self, validator: ValidatorId) -> Option<VnodeInit> {
        let signing_key = self.vnode_keys.get(&validator).cloned().or_else(|| {
            warn!(
                validator = validator.inner(),
                "No local signing key for a drained validator; not following it"
            );
            None
        })?;
        Some(seat_follower(SeatFollower {
            beacon_storage: self.process.beacon_storage().as_ref(),
            beacon_network: self.beacon_network.clone(),
            beacon_config_hash: self.beacon_config_hash,
            now: consensus_clock(self.genesis_offset_ms),
            validator,
            signing_key,
        }))
    }

    /// Begin following the beacon for `validator` in the pool — it drained
    /// off its last shard and would otherwise go dark, never raising its own
    /// re-seat trigger. No-op if it is already a follower.
    pub(super) fn follow_in_pool(&mut self, validator: ValidatorId) {
        let mut validators = self
            .pool
            .as_ref()
            .map(|p| p.validators.clone())
            .unwrap_or_default();
        if validators.contains(&validator) {
            return;
        }
        validators.push(validator);
        self.rebuild_pool(&validators);
        info!(
            validator = validator.inner(),
            "Following the beacon in the pool after draining off the last shard"
        );
    }

    /// Drop `validator` from the pool — it was seated onto a shard, so its
    /// shard vnode now drives its beacon. No-op if it isn't a follower; the
    /// pool thread tears down once its last follower leaves.
    pub(super) fn unfollow_in_pool(&mut self, validator: ValidatorId) {
        let Some(pool) = self.pool.as_ref() else {
            return;
        };
        if !pool.validators.contains(&validator) {
            return;
        }
        let validators: Vec<ValidatorId> = pool
            .validators
            .iter()
            .copied()
            .filter(|&v| v != validator)
            .collect();
        self.rebuild_pool(&validators);
    }

    /// Whether `validator` runs a vnode on any shard this host still hosts.
    pub(super) fn validator_on_any_shard(&self, validator: ValidatorId) -> bool {
        let id = validator.inner();
        self.shards.values().any(|t| t.validator_ids.contains(&id))
    }
}
