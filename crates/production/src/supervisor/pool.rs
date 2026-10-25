//! The supervisor's beacon half: the pinned thread lifecycle for a host's
//! beacon loop.
//!
//! Every host runs one beacon thread from startup to shutdown. It owns the
//! host's fold and one participant per signing key the process holds,
//! which is fixed for the life of the process, so the loop is never
//! rebuilt. Chains register and deregister with it over its channel.

use std::sync::Arc;

use crossbeam::channel::{Sender, unbounded};
use tokio::sync::oneshot;
use tracing::warn;

use super::ShardSupervisor;
use crate::runner::{BeaconLoopConfig, ProdBeaconLoop, spawn_beacon_loop};

/// The host's pinned beacon thread plus the handle to stop it.
pub(super) struct BeaconThread {
    join: std::thread::JoinHandle<()>,
    shutdown_tx: Sender<()>,
}

impl ShardSupervisor {
    /// Spawn the host's beacon thread from the startup `BeaconLoop`. The
    /// returned receiver resolves once the thread ends, however it ends.
    pub(crate) fn install_beacon_loop(&mut self, beacon: ProdBeaconLoop) -> oneshot::Receiver<()> {
        let (exited, exited_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = unbounded();
        let cfg = BeaconLoopConfig {
            beacon_rx: self.beacon_event_rx.clone(),
            shutdown_rx,
            participation_tx: self.participation_tx.clone(),
            genesis_offset_ms: self.genesis_offset_ms,
            headers: Arc::clone(&self.publishers.headers),
        };
        let join = spawn_beacon_loop(beacon, cfg, exited);
        self.beacon = Some(BeaconThread { join, shutdown_tx });
        exited_rx
    }

    /// Stop the beacon thread if one runs, joining it. The thread closes
    /// every participant's release gate on its way out.
    pub(super) fn teardown_beacon_loop(&mut self) {
        if let Some(thread) = self.beacon.take() {
            let _ = thread.shutdown_tx.send(());
            if thread.join.join().is_err() {
                warn!("Beacon thread panicked before teardown");
            }
        }
    }
}
