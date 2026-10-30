//! Execution-flow dispatch arms.
//!
//! Covers tick-based voting (votes received, aggregated, certificate
//! verified) and the engine results path (`ExecutionBatchCompleted`).
//!
//! An admitted certificate from another shard also acknowledges the
//! outbound batches this shard sent it: its outcomes go straight to the
//! outbound provision tracker.

use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::TopologySchedule;

use super::ShardParticipation;

impl ShardParticipation {
    /// Dispatch an execution-category `ProtocolEvent`.
    pub(in crate::state) fn handle_execution(
        &mut self,
        topology_schedule: &TopologySchedule,
        event: ProtocolEvent,
    ) -> Vec<Action> {
        match event {
            ProtocolEvent::ExecutionBatchCompleted { tick, outcome } => {
                // Results arriving can (a) finalize a tick whose local
                // certificate landed ahead of the engine, (b) unblock vote
                // emission, (c) release the next queued tick.
                let mut actions = self.execution_coordinator.on_execution_batch_completed(
                    topology_schedule,
                    tick,
                    outcome,
                );
                actions.extend(
                    self.execution_coordinator
                        .emit_vote_actions(topology_schedule),
                );
                actions
            }
            ProtocolEvent::ExecutionVoteReceived { vote } => self
                .execution_coordinator
                .on_execution_vote(topology_schedule, vote),
            ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                tick_id,
                block_hash,
                verified_votes,
            } => self.execution_coordinator.on_votes_verified(
                topology_schedule,
                tick_id,
                block_hash,
                verified_votes,
            ),
            ProtocolEvent::ExecutionCertificateAggregated {
                tick_id,
                certificate,
            } => self.execution_coordinator.on_certificate_aggregated(
                topology_schedule,
                &tick_id,
                &certificate,
            ),
            ProtocolEvent::ExecutionCertificatesReceived { certificates } => {
                let mut actions = Vec::new();
                for cert in certificates {
                    actions.extend(
                        self.execution_coordinator
                            .on_execution_certificate(topology_schedule, cert),
                    );
                }
                actions
            }
            ProtocolEvent::FinalizationsReceived { finalizations } => {
                let mut actions = Vec::new();
                for tick in finalizations {
                    actions.extend(
                        self.execution_coordinator
                            .admit_finalization(topology_schedule, tick),
                    );
                }
                actions
            }
            ProtocolEvent::FinalizationVerified { result } => {
                self.execution_coordinator.on_finalization_verified(result)
            }
            ProtocolEvent::LegsHalfBuilt { tick, tip, half } => self
                .execution_coordinator
                .on_legs_half_built(tick, tip, half),
            ProtocolEvent::ExecutionCertificateSignatureVerified { result } => self
                .execution_coordinator
                .on_certificate_verified(topology_schedule, result),
            ProtocolEvent::ExecutionCertificateAdmitted { certificate } => {
                // A remote certificate's outcomes acknowledge the outbound
                // batches this shard sent it. The tracker keys on the
                // transaction, so an outcome for nothing sent is a no-op.
                if certificate.shard_id() != self.local_shard {
                    self.outbound_provisions
                        .on_ec_observed(certificate.shard_id(), certificate.tx_outcomes());
                }
                // Remote EC abort propagation may unlock local accumulators — re-scan.
                self.execution_coordinator
                    .emit_vote_actions(topology_schedule)
            }
            ProtocolEvent::ExecutionBatchUnavailable {
                tick,
                tick_ts,
                env,
                requests,
                included,
                package,
            } => self
                .execution_coordinator
                .on_execution_batch_unavailable(tick, tick_ts, env, requests, included, package),
            _ => unreachable!("non-execution event routed to handle_execution"),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use hyperscale_core::{ProtocolEvent, StateMachine};
    use hyperscale_hbor::Capped;
    use hyperscale_types::{
        AggregateSignature, BlockHeight, ExecutionCertificate, ExecutionOutcome, GlobalReceiptRoot,
        Hash, LocalTimestamp, MerkleInclusionProof, ProvisionEntry, Provisions, ShardId,
        SignerBitfield, TickId, TxHash, TxOutcome, Verified, WeightedTimestamp,
    };

    use crate::state::NodeStateMachine;
    use crate::state::test_support::TestNode;

    fn make_ec(
        shard: ShardId,
        height: BlockHeight,
        outcomes: Vec<TxOutcome>,
    ) -> Arc<Verified<ExecutionCertificate>> {
        let tick_id = TickId::new(shard, height);
        Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(0),
            GlobalReceiptRoot::ZERO,
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        )))
    }

    /// A node on the root shard that has broadcast one batch carrying
    /// `tx` to the leaf `target`.
    fn sent_one_batch(target: ShardId, tx: TxHash) -> NodeStateMachine {
        let TestNode { mut node, .. } = TestNode::builder().build();
        let provisions = Arc::new(Verified::new_unchecked_for_test(Provisions::new(
            ShardId::ROOT,
            target,
            BlockHeight::new(1),
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::dummy(),
            Capped::from_array([ProvisionEntry::new(tx, Capped::empty())]),
        )));
        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::OutboundProvisionBroadcast {
                provisions,
                target_shard: target,
            },
        );
        assert_eq!(
            node.outbound_provisions().memory_stats().tracked_provisions,
            1
        );
        node
    }

    fn admit(node: &mut NodeStateMachine, certificate: Arc<Verified<ExecutionCertificate>>) {
        let _ = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::ExecutionCertificateAdmitted { certificate },
        );
    }

    /// The target shard's certificate naming the transaction a batch
    /// carried acknowledges the batch, which the tracker then drops.
    #[test]
    fn a_remote_certificate_acknowledges_the_batch_sent_to_it() {
        let target = ShardId::leaf(1, 1);
        let tx = TxHash::from(Hash::from_bytes(b"outbound-tx"));
        let mut node = sent_one_batch(target, tx);

        admit(
            &mut node,
            make_ec(
                target,
                BlockHeight::new(1),
                vec![TxOutcome::new(tx, ExecutionOutcome::Failed)],
            ),
        );

        assert_eq!(
            node.outbound_provisions().memory_stats().tracked_provisions,
            0
        );
    }

    /// A certificate of this shard's own acknowledges nothing it sent,
    /// even where it names the same transaction.
    #[test]
    fn a_local_certificate_acknowledges_no_outbound_batch() {
        let tx = TxHash::from(Hash::from_bytes(b"outbound-tx"));
        let mut node = sent_one_batch(ShardId::leaf(1, 1), tx);

        admit(
            &mut node,
            make_ec(
                ShardId::ROOT,
                BlockHeight::new(1),
                vec![TxOutcome::new(tx, ExecutionOutcome::Failed)],
            ),
        );

        assert_eq!(
            node.outbound_provisions().memory_stats().tracked_provisions,
            1
        );
    }
}
