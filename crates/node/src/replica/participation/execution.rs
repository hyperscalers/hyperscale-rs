//! Execution-flow handlers.
//!
//! Covers tick-based voting (votes received, aggregated, certificate
//! verified) and the engine results path (`ExecutionBatchCompleted`).
//!
//! An admitted certificate from another shard also acknowledges the
//! outbound batches this shard sent it: its outcomes go straight to the
//! outbound provision tracker.

use std::sync::Arc;

use hyperscale_core::{Action, TickBatchOutcome};
use hyperscale_types::{
    BlockHeight, ExecutionCertificate, Finalization, TopologySchedule, Verifiable,
};

use super::ShardParticipation;

impl ShardParticipation {
    /// One tick's results arrived. They can (a) finalize a tick whose
    /// local certificate landed ahead of the engine, (b) unblock vote
    /// emission, (c) release the next queued tick.
    pub(in crate::replica) fn on_execution_batch_completed(
        &mut self,
        sched: &TopologySchedule,
        tick: BlockHeight,
        outcome: TickBatchOutcome,
    ) -> Vec<Action> {
        let mut actions = self
            .execution_coordinator
            .on_execution_batch_completed(sched, tick, outcome);
        actions.extend(self.execution_coordinator.emit_vote_actions(sched));
        actions
    }

    /// A certificate was admitted. One from another shard acknowledges
    /// the outbound batches this shard sent it; the tracker keys on the
    /// transaction, so an outcome for nothing sent is a no-op.
    pub(in crate::replica) fn on_execution_certificate_admitted(
        &mut self,
        sched: &TopologySchedule,
        certificate: &ExecutionCertificate,
    ) -> Vec<Action> {
        if certificate.shard_id() != self.local_shard {
            self.outbound_provisions
                .on_ec_observed(certificate.shard_id(), certificate.tx_outcomes());
        }
        // Remote EC abort propagation may unlock local accumulators — re-scan.
        self.execution_coordinator.emit_vote_actions(sched)
    }

    /// Hand each received certificate to the execution coordinator.
    pub(in crate::replica) fn on_execution_certificates_received(
        &mut self,
        sched: &TopologySchedule,
        certificates: Vec<Verifiable<ExecutionCertificate>>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for cert in certificates {
            actions.extend(
                self.execution_coordinator
                    .on_execution_certificate(sched, cert),
            );
        }
        actions
    }

    /// Admit each received finalization.
    pub(in crate::replica) fn on_finalizations_received(
        &mut self,
        sched: &TopologySchedule,
        finalizations: Vec<Arc<Verifiable<Finalization>>>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for tick in finalizations {
            actions.extend(self.execution_coordinator.admit_finalization(sched, tick));
        }
        actions
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

    use crate::replica::NodeStateMachine;
    use crate::replica::test_support::TestNode;

    fn make_ec(
        shard: ShardId,
        height: BlockHeight,
        outcomes: Vec<TxOutcome>,
    ) -> Verified<ExecutionCertificate> {
        let tick_id = TickId::new(shard, height);
        Verified::new_unchecked_for_test(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(0),
            GlobalReceiptRoot::ZERO,
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        ))
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

    fn admit(node: &mut NodeStateMachine, certificate: Verified<ExecutionCertificate>) {
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
