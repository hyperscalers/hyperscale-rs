//! Provision-flow dispatch arms.
//!
//! Covers both inbound provision delivery (received → verified → admitted)
//! and outbound provision tracking (broadcasts the local shard issued, and
//! the remote ECs that ack them).

use super::NodeStateMachine;
use hyperscale_core::{Action, ProtocolEvent};

impl NodeStateMachine {
    /// Dispatch a provision-category `ProtocolEvent`.
    pub(super) fn handle_provisions(&mut self, event: ProtocolEvent) -> Vec<Action> {
        match event {
            ProtocolEvent::ProvisionsReceived { provisions } => self
                .provisions
                .on_state_provisions_received(self.topology.snapshot(), provisions),
            ProtocolEvent::StateProvisionsVerified {
                provisions,
                committed_header,
                valid,
            } => self.provisions.on_state_provisions_verified(
                self.topology.snapshot(),
                provisions,
                committed_header.as_ref(),
                valid,
                self.now,
            ),
            ProtocolEvent::ProvisionsAdmitted { provisions, .. } => {
                let actions = self
                    .bft
                    .on_provisions_admitted(self.topology.snapshot(), &[provisions]);
                self.bft.queue_ready_proposal();
                actions
            }
            ProtocolEvent::OutboundProvisionBroadcast {
                provisions,
                target_shard,
            } => {
                self.outbound_provisions
                    .on_broadcast(&provisions, target_shard);
                vec![]
            }
            ProtocolEvent::OutboundEcObserved {
                target_shard,
                tx_outcomes,
            } => {
                self.outbound_provisions
                    .on_ec_observed(target_shard, &tx_outcomes);
                vec![]
            }
            _ => unreachable!("non-provision event routed to handle_provisions"),
        }
    }
}
