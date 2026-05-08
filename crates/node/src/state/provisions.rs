//! Provision-flow dispatch arms.
//!
//! Covers both inbound provision delivery (received → verified → admitted)
//! and outbound provision tracking (broadcasts the local shard issued, and
//! the remote ECs that ack them).

use hyperscale_core::{Action, ProtocolEvent};

use super::NodeStateMachine;

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_core::{Action, ProtocolEvent, StateMachine};
    use hyperscale_types::{
        BlockHeight, MerkleInclusionProof, Provisions, ShardGroupId, WeightedTimestamp,
    };

    use super::super::test_support::TestNode;

    /// `ProvisionsAdmitted` latches a proposal-retry the same way
    /// `TransactionsAdmitted` does. Verify the latch+post-dispatch chain
    /// surfaces a `BuildProposal` when the local validator is the
    /// round-0 height-1 proposer.
    #[test]
    fn provisions_admitted_drives_proposal_through_post_dispatch_hook() {
        // committee[1] = ValidatorId::new(1) is the round-0 height-1
        // proposer; pick local_idx=1 so we are it.
        let TestNode { mut node, .. } = TestNode::builder().local_idx(1).build();

        let provisions = Arc::new(Provisions::new(
            ShardGroupId::new(1), // source
            ShardGroupId::new(0), // target (local)
            BlockHeight::new(1),
            MerkleInclusionProof::dummy(),
            vec![],
        ));

        let actions = node.handle(ProtocolEvent::ProvisionsAdmitted {
            provisions,
            source_block_ts: WeightedTimestamp::from_millis(0),
        });

        let saw_proposal = actions
            .iter()
            .any(|a| matches!(a, Action::BuildProposal { .. }));
        assert!(
            saw_proposal,
            "expected BuildProposal after ProvisionsAdmitted on a leader; got {actions:?}",
        );
    }
}
