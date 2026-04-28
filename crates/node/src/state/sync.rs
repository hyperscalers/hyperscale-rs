//! Sync-flow dispatch arms.
//!
//! Sync recovery fans out across multiple coordinators when it completes —
//! BFT exits sync mode, while remote-headers and provisions flush their
//! expected sets so we can immediately participate in execution for blocks
//! within the `WAVE_TIMEOUT` window.

use super::NodeStateMachine;
use hyperscale_core::{Action, ProtocolEvent};

impl NodeStateMachine {
    /// Dispatch a sync-category `ProtocolEvent`.
    pub(super) fn handle_sync(&mut self, event: ProtocolEvent) -> Vec<Action> {
        match event {
            ProtocolEvent::SyncBlockReadyToApply { certified } => self
                .bft
                .on_sync_block_ready_to_apply(self.topology.snapshot(), certified),
            // Verification completion is handled by IoLoop directly.
            ProtocolEvent::SyncEcVerificationComplete { .. } => vec![],
            // SyncProtocol finished fetching — tell BFT to exit sync mode so
            // it can re-enter sync if still behind, or resume normal consensus.
            ProtocolEvent::SyncProtocolComplete { .. } => {
                self.bft.on_sync_complete(self.topology.snapshot())
            }
            // Sync recovery complete — flush expected provisions and remote
            // headers immediately so we can participate in execution for recent
            // blocks within the WAVE_TIMEOUT window.
            ProtocolEvent::SyncResumed => {
                let topo = self.topology.snapshot();
                let mut actions = self.remote_headers.flush_expected_headers(topo);
                actions.extend(self.provisions.flush_expected_provisions(topo));
                actions
            }
            ProtocolEvent::ChainMetadataFetched { height, hash, qc } => self
                .bft
                .on_chain_metadata_fetched(self.topology.snapshot(), height, hash, qc),
            _ => unreachable!("non-sync event routed to handle_sync"),
        }
    }
}
