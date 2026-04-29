//! Sync-flow dispatch arms.
//!
//! When `SyncProtocolComplete` fires we fan out across all three
//! coordinators in one pass: BFT exits sync mode and re-issues any
//! pending block fetches it had suppressed; remote-headers and
//! provisions flush their expected sets so we can immediately
//! participate in execution for blocks within the `WAVE_TIMEOUT` window.

use super::NodeStateMachine;
use hyperscale_core::{Action, ProtocolEvent};

impl NodeStateMachine {
    /// Dispatch a sync-category `ProtocolEvent`.
    pub(super) fn handle_sync(&mut self, event: ProtocolEvent) -> Vec<Action> {
        match event {
            ProtocolEvent::SyncBlockReadyToApply { certified } => self
                .bft
                .on_sync_block_ready_to_apply(self.topology.snapshot(), certified),
            // SyncProtocol finished fetching: exit BFT sync mode + flush
            // expected provisions + flush expected headers, all in one
            // pass.
            ProtocolEvent::SyncProtocolComplete { .. } => {
                let topo = self.topology.snapshot();
                let mut actions = self.bft.on_sync_complete(topo);
                actions.extend(self.remote_headers.flush_expected_headers(topo));
                actions.extend(self.provisions.flush_expected_provisions(topo));
                actions
            }
            ProtocolEvent::CommittedStateRestored { height, hash, qc } => self
                .bft
                .on_committed_state_restored(self.topology.snapshot(), height, hash, qc),
            // Acknowledged but unused for now. Commit 4 wires
            // `RemoteHeaderCoordinator` to clear its per-shard "syncing"
            // flag here.
            ProtocolEvent::RemoteHeaderSyncProtocolComplete { .. } => vec![],
            _ => unreachable!("non-sync event routed to handle_sync"),
        }
    }
}
