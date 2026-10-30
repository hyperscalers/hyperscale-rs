//! Provision-flow handlers.
//!
//! Covers both inbound provision delivery (received → verified → admitted)
//! and outbound provision tracking (broadcasts the local shard issued, and
//! the remote ECs that ack them).

use std::sync::Arc;

use hyperscale_core::Action;
use hyperscale_metrics::record_crossing_push_dropped;
use hyperscale_types::{Provisions, StateClaim, TopologySchedule, Verifiable};

use super::ShardParticipation;

impl ShardParticipation {
    /// Crossing readings a counterpart pushed. A claim at a height this
    /// node fences against never reaches a block, so it is not worth
    /// parking either.
    pub(in crate::replica) fn on_crossing_readings(
        &mut self,
        sched: &TopologySchedule,
        claims: Vec<StateClaim>,
    ) -> Vec<Action> {
        let fence = &self.fork_fence;
        let claims: Vec<_> = claims
            .into_iter()
            .filter(|claim| {
                let fenced = fence.is_fenced(claim.anchor.shard, claim.anchor.height);
                if fenced {
                    record_crossing_push_dropped("fenced");
                }
                !fenced
            })
            .collect();
        let actions = self
            .execution_coordinator
            .on_crossing_readings(sched, claims);
        self.shard_coordinator.queue_ready_proposal();
        actions
    }

    /// A verified bundle is engagement evidence: promote any parked
    /// cross-shard transaction it names, before the proposal latch
    /// gathers ready transactions, so the bundle and its transactions
    /// pair in one proposal.
    pub(in crate::replica) fn on_provisions_admitted(
        &mut self,
        sched: &TopologySchedule,
        provisions: Arc<Verifiable<Provisions>>,
    ) -> Vec<Action> {
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

    use crate::replica::test_support::TestNode;

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
