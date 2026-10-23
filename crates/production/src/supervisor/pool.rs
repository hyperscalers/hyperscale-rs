//! The supervisor's beacon half: the pinned thread lifecycle for a host's
//! beacon loop and the shard-less, beacon-following vnodes it drives.
//!
//! Every host runs a beacon thread. A validator that drains off its last
//! shard keeps following the beacon on it — it must fold placements to
//! raise its own re-seat trigger — and a seat retires its follower again.
//! The loop is rebuilt, never mutated: a change to its follower set tears
//! the thread down and spawns a fresh one over the adjusted set, resuming
//! cheaply from the host's warm beacon storage.

use std::sync::Arc;

use crossbeam::channel::{Sender, unbounded};
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_node::beacon_loop::BeaconLoop;
use hyperscale_node::{SeatFollower, VnodeInit, seat_follower};
use hyperscale_types::ValidatorId;
use tracing::{info, warn};

use super::ShardSupervisor;
use crate::runner::{BeaconLoopConfig, ProdBeaconLoop, consensus_clock, spawn_beacon_loop};

/// The host's pinned beacon thread plus the handle to stop it, and the
/// follower validators it currently drives — a membership change rebuilds
/// the loop with the adjusted set.
pub(super) struct BeaconThread {
    join: std::thread::JoinHandle<()>,
    shutdown_tx: Sender<()>,
    /// Validators currently followed on the loop. A drain off the last
    /// shard adds one; a seat removes one.
    validators: Vec<ValidatorId>,
}

impl ShardSupervisor {
    /// Spawn the host's beacon thread from the startup `BeaconLoop`. A
    /// beacon thread already running is left in place.
    pub(crate) fn install_beacon_loop(&mut self, beacon: ProdBeaconLoop) {
        if self.beacon.is_some() {
            warn!("install_beacon_loop called while a beacon thread already runs; ignored");
            return;
        }
        self.start_beacon_thread(beacon);
    }

    /// Spawn a pinned thread for `beacon`, recording its handle and
    /// follower set. The thread drains a clone of the host's beacon
    /// channel; the host-level gossip handler pushes committed beacon
    /// blocks onto the paired sender while the loop has a follower.
    fn start_beacon_thread(&mut self, beacon: ProdBeaconLoop) {
        let validators: Vec<ValidatorId> = beacon.validators().collect();
        let (shutdown_tx, shutdown_rx) = unbounded();
        let cfg = BeaconLoopConfig {
            beacon_rx: self.beacon_event_rx.clone(),
            shutdown_rx,
            participation_tx: self.participation_tx.clone(),
            genesis_offset_ms: self.genesis_offset_ms,
        };
        let route = !validators.is_empty();
        let join = spawn_beacon_loop(beacon, cfg);
        self.beacon = Some(BeaconThread {
            join,
            shutdown_tx,
            validators,
        });
        self.process.set_beacon_route_active(route);
    }

    /// Stop the beacon thread if one runs, joining it. The thread closes
    /// every follower's release gate on its way out.
    pub(super) fn teardown_beacon_loop(&mut self) {
        if let Some(thread) = self.beacon.take() {
            // Stop routing before the drain ends so the channel can't back
            // up between the shutdown signal and the thread's exit.
            self.process.set_beacon_route_active(false);
            let _ = thread.shutdown_tx.send(());
            if thread.join.join().is_err() {
                warn!("Beacon thread panicked before teardown");
            }
        }
    }

    /// Rebuild the beacon thread to follow exactly `validators`: tear the
    /// current thread down, build a fresh follower per validator from the
    /// host's warm beacon storage, and spawn a new thread. Tearing down
    /// and rebuilding (rather than mutating a running thread) keeps the
    /// follower set a single owned value; a follower resumes cheaply from
    /// the warm storage tip.
    fn rebuild_beacon_loop(&mut self, validators: &[ValidatorId]) {
        self.teardown_beacon_loop();
        let vnodes: Vec<_> = validators
            .iter()
            .filter_map(|&validator| self.build_follower(validator))
            .map(VnodeInit::into_vnode)
            .collect();
        let beacon = BeaconLoop::new(Arc::clone(&self.process), vnodes, &self.node_config);
        self.start_beacon_thread(beacon);
    }

    /// Build one shard-less follower for `validator` from the host's warm
    /// beacon storage. `None` when the validator has no local signing key
    /// (it isn't ours to follow for).
    fn build_follower(&self, validator: ValidatorId) -> Option<VnodeInit> {
        let signer = self.vnode_keys.get(&validator).cloned().or_else(|| {
            warn!(
                validator = validator.inner(),
                "No local signing key for a drained validator; not following it"
            );
            None
        })?;
        Some(seat_follower(SeatFollower {
            verifier: Arc::new(BlsVerifier),
            beacon_storage: self.process.beacon_storage().as_ref(),
            beacon_network: self.beacon_network.clone(),
            beacon_config_hash: self.beacon_config_hash,
            now: consensus_clock(self.genesis_offset_ms),
            validator,
            signer,
        }))
    }

    /// Begin following the beacon for `validator` on the beacon loop — it
    /// drained off its last shard and would otherwise go dark, never
    /// raising its own re-seat trigger. No-op if it is already a follower.
    pub(super) fn follow_in_pool(&mut self, validator: ValidatorId) {
        let mut validators = self
            .beacon
            .as_ref()
            .map_or_default(|thread| thread.validators.clone());
        if validators.contains(&validator) {
            return;
        }
        validators.push(validator);
        self.rebuild_beacon_loop(&validators);
        info!(
            validator = validator.inner(),
            "Following the beacon on the beacon loop after draining off the last shard"
        );
    }

    /// Drop `validator`'s follower — it was seated onto a shard, so its
    /// shard vnode now drives its beacon. No-op if it isn't a follower.
    pub(super) fn unfollow_in_pool(&mut self, validator: ValidatorId) {
        let Some(thread) = self.beacon.as_ref() else {
            return;
        };
        if !thread.validators.contains(&validator) {
            return;
        }
        let validators: Vec<ValidatorId> = thread
            .validators
            .iter()
            .copied()
            .filter(|&v| v != validator)
            .collect();
        self.rebuild_beacon_loop(&validators);
    }

    /// Whether `validator` runs a vnode on any shard this host still hosts.
    pub(super) fn validator_on_any_shard(&self, validator: ValidatorId) -> bool {
        let id = validator.inner();
        self.shards.values().any(|t| t.validator_ids.contains(&id))
    }
}
