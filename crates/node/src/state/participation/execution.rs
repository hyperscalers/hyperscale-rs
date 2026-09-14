//! Execution-flow dispatch arms.
//!
//! Covers tick-based voting (votes received, aggregated, certificate
//! verified) and the engine results path (`ExecutionBatchCompleted`).
//!
//! Cross-shard EC admission has a quirk: if an admitted EC names the local
//! shard among `tick_id.remote_shards`, that EC's `tx_outcomes` ack the
//! outbound batches we sent — the admission arm captures that ACK and emits
//! a follow-up `OutboundEcObserved` to feed the outbound provision tracker.

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
            ProtocolEvent::VerifiedExecutionVoteReceived { vote } => self
                .execution_coordinator
                .on_verified_execution_vote(topology_schedule, vote),
            ProtocolEvent::UnverifiedExecutionVoteReceived { vote } => self
                .execution_coordinator
                .on_unverified_execution_vote(topology_schedule, vote),
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
            ProtocolEvent::ExecutionCertificateSignatureVerified { result } => self
                .execution_coordinator
                .on_certificate_verified(topology_schedule, result),
            ProtocolEvent::ExecutionCertificateAdmitted { certificate } => {
                let local_shard = self.local_shard;
                let mut actions = Vec::new();
                // If the EC is for a remote tick where we were a source, the
                // target shard's tx_outcomes acknowledge outbound batches we
                // sent. Surface the ACK to the outbound tracker.
                // A remote batch acknowledging outbound work of ours: its
                // outcomes name transactions, and the tracker keys on
                // those, so an outcome for nothing we sent is a no-op
                // rather than something to filter on identity here.
                if certificate.shard_id() != local_shard && !certificate.tx_outcomes().is_empty() {
                    actions.push(Action::Continuation(ProtocolEvent::OutboundEcObserved {
                        target_shard: certificate.shard_id(),
                        tx_outcomes: certificate.tx_outcomes().clone(),
                    }));
                }
                // Remote EC abort propagation may unlock local accumulators — re-scan.
                actions.extend(
                    self.execution_coordinator
                        .emit_vote_actions(topology_schedule),
                );
                actions
            }
            _ => unreachable!("non-execution event routed to handle_execution"),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use hyperscale_core::{Action, ProtocolEvent, StateMachine};
    use hyperscale_types::{
        AggregateSignature, BlockHeight, ExecutionCertificate, ExecutionOutcome, GlobalReceiptRoot,
        LocalTimestamp, ShardId, SignerBitfield, TickId, TxHash, TxOutcome, Verified,
        WeightedTimestamp,
    };

    use crate::state::test_support::TestNode;
    use crate::{assert_no_emit, extract_one};

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
            outcomes,
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        )))
    }

    /// `ExecutionCertificateAdmitted` for a remote-shard certificate must
    /// surface an `OutboundEcObserved` continuation carrying its
    /// `tx_outcomes` — that's how the outbound provision tracker learns
    /// its batches were ack'd.
    #[test]
    fn execution_certificate_admitted_emits_outbound_ec_continuation_when_we_were_a_source() {
        // Local home shard is the root; the EC names a distinct leaf shard.
        let TestNode { mut node, .. } = TestNode::builder().build();

        let ec = make_ec(
            ShardId::leaf(1, 1),
            BlockHeight::new(1),
            vec![TxOutcome::new(TxHash::ZERO, ExecutionOutcome::Failed)],
        );

        let actions = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::ExecutionCertificateAdmitted { certificate: ec },
        );

        let cont = extract_one!(
            actions,
            Action::Continuation(ProtocolEvent::OutboundEcObserved { .. })
        );
        if let Action::Continuation(ProtocolEvent::OutboundEcObserved {
            target_shard,
            tx_outcomes,
        }) = cont
        {
            assert_eq!(*target_shard, ShardId::leaf(1, 1));
            assert_eq!(tx_outcomes.len(), 1);
        } else {
            unreachable!()
        }
    }

    /// Same-shard EC: the EC's `shard_id` matches local, so the
    /// "remote ack" path doesn't apply and no `OutboundEcObserved`
    /// continuation must be emitted.
    #[test]
    fn execution_certificate_admitted_skips_continuation_for_same_shard_ec() {
        let TestNode { mut node, .. } = TestNode::new();

        let ec = make_ec(ShardId::ROOT, BlockHeight::new(1), vec![]);

        let actions = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::ExecutionCertificateAdmitted { certificate: ec },
        );

        assert_no_emit!(
            actions,
            Action::Continuation(ProtocolEvent::OutboundEcObserved { .. })
        );
    }

    /// A certificate attesting nothing carries no acknowledgement, so
    /// there is nothing to surface. Which of its outcomes we were a source
    /// for is the outbound tracker's question — it keys on the
    /// transaction and ignores one it never sent — rather than one this
    /// seam can answer from the certificate's identity.
    #[test]
    fn execution_certificate_admitted_surfaces_nothing_for_an_empty_certificate() {
        let TestNode { mut node, .. } = TestNode::builder().build();

        let ec = make_ec(ShardId::leaf(1, 0), BlockHeight::new(1), vec![]);

        let actions = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::ExecutionCertificateAdmitted { certificate: ec },
        );

        assert_no_emit!(
            actions,
            Action::Continuation(ProtocolEvent::OutboundEcObserved { .. })
        );
    }
}
