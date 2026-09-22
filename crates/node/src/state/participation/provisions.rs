//! Provision-flow dispatch arms.
//!
//! Covers both inbound provision delivery (received → verified → admitted)
//! and outbound provision tracking (broadcasts the local shard issued, and
//! the remote ECs that ack them).

use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::TopologySchedule;

use super::ShardParticipation;

impl ShardParticipation {
    /// Dispatch a provision-category `ProtocolEvent`.
    pub(in crate::state) fn handle_provisions(
        &mut self,
        sched: &TopologySchedule,
        event: ProtocolEvent,
    ) -> Vec<Action> {
        match event {
            ProtocolEvent::UnverifiedProvisionsReceived { provisions } => self
                .provisions_coordinator
                .on_state_provisions_received(sched, std::sync::Arc::unwrap_or_clone(provisions)),
            ProtocolEvent::PulledProvisionsReceived {
                provisions,
                anchor,
                records,
            } => self.provisions_coordinator.on_pulled_provisions_received(
                anchor,
                records,
                provisions.map(std::sync::Arc::unwrap_or_clone),
            ),
            ProtocolEvent::VerifiedProvisionsReceived { provisions } => self
                .provisions_coordinator
                .on_verified_state_provisions_received(sched, provisions, self.now),
            ProtocolEvent::StateProvisionsVerified { result, anchor } => self
                .provisions_coordinator
                .on_state_provisions_verified(result, anchor, self.now),
            ProtocolEvent::ProvisionsAdmitted { provisions, .. } => {
                // A verified bundle is engagement evidence: promote any
                // parked cross-shard transaction it names, before the
                // proposal latch below gathers ready transactions — the
                // bundle and its transactions then pair in one proposal.
                self.mempool_coordinator.on_engagement_evidence(
                    sched.head().shard_trie(),
                    provisions.source_shard(),
                    provisions.transactions().iter().map(|entry| entry.tx_hash),
                );
                let actions = self
                    .shard_coordinator
                    .on_provisions_admitted(sched, &[provisions]);
                self.shard_coordinator.queue_ready_proposal();
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
    use hyperscale_hbor::Capped;
    use hyperscale_types::{
        BlockHeight, LocalTimestamp, MerkleInclusionProof, Provisions, ShardId, Verified,
        WeightedTimestamp,
    };

    use crate::state::test_support::TestNode;

    /// `ProvisionsAdmitted` latches a proposal-retry the same way
    /// `TransactionsAdmitted` does. Verify the latch+post-dispatch chain
    /// surfaces a `BuildProposal` when the local validator is the
    /// height-1 proposer.
    #[test]
    fn provisions_admitted_drives_proposal_through_post_dispatch_hook() {
        // Rounds increase per block, so height 1 is round 1: committee[1 % 4]
        // = committee[1] = ValidatorId::new(1) is the leader; pick local_idx=1
        // so we are it.
        let TestNode { mut node, .. } = TestNode::builder().local_idx(1).build();

        let provisions = Arc::new(
            Verified::new_unchecked_for_test(Provisions::new(
                ShardId::leaf(1, 1), // source
                ShardId::ROOT,       // target (local)
                BlockHeight::new(1),
                WeightedTimestamp::ZERO,
                MerkleInclusionProof::dummy(),
                Capped::from_array([]),
            ))
            .into(),
        );

        let actions = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::ProvisionsAdmitted {
                provisions,
                source_block_ts: WeightedTimestamp::from_millis(0),
            },
        );

        let saw_proposal = actions
            .iter()
            .any(|a| matches!(a, Action::BuildProposal { .. }));
        assert!(
            saw_proposal,
            "expected BuildProposal after ProvisionsAdmitted on a leader; got {actions:?}",
        );
    }
}
