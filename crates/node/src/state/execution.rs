//! Execution-flow dispatch arms.
//!
//! Covers wave-based voting (votes received, aggregated, certificate
//! verified) and the engine results path (`ExecutionBatchCompleted`).
//!
//! Cross-shard EC admission has a quirk: if an admitted EC names the local
//! shard among `wave_id.remote_shards`, that EC's `tx_outcomes` ack the
//! outbound batches we sent — the admission arm captures that ACK and emits
//! a follow-up `OutboundEcObserved` to feed the outbound provision tracker.

use hyperscale_core::{Action, ProtocolEvent};

use super::NodeStateMachine;

impl NodeStateMachine {
    /// Dispatch an execution-category `ProtocolEvent`.
    pub(super) fn handle_execution(&mut self, event: ProtocolEvent) -> Vec<Action> {
        match event {
            ProtocolEvent::ExecutionBatchCompleted {
                wave_id,
                results,
                tx_outcomes,
            } => {
                // Results arriving can (a) finalize a wave whose local EC
                // landed ahead of the engine, (b) unblock new vote emission.
                let mut actions = self.execution_coordinator.on_execution_batch_completed(
                    &wave_id,
                    results,
                    tx_outcomes,
                );
                actions.extend(
                    self.execution_coordinator
                        .emit_vote_actions(&self.topology_snapshot),
                );
                actions
            }
            ProtocolEvent::ExecutionVoteReceived { vote } => self
                .execution_coordinator
                .on_execution_vote(&self.topology_snapshot, vote),
            ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                wave_id,
                block_hash,
                verified_votes,
            } => self.execution_coordinator.on_votes_verified(
                &self.topology_snapshot,
                wave_id,
                block_hash,
                verified_votes,
            ),
            ProtocolEvent::ExecutionCertificateAggregated {
                wave_id,
                certificate,
            } => self.execution_coordinator.on_certificate_aggregated(
                &self.topology_snapshot,
                &wave_id,
                &certificate,
            ),
            ProtocolEvent::ExecutionCertificatesReceived { certificates } => {
                let topology = &self.topology_snapshot;
                let mut actions = Vec::new();
                for cert in certificates {
                    actions.extend(
                        self.execution_coordinator
                            .on_wave_certificate(topology, cert),
                    );
                }
                actions
            }
            ProtocolEvent::FinalizedWavesReceived { waves } => {
                let topology = &self.topology_snapshot;
                let mut actions = Vec::new();
                for wave in waves {
                    actions.extend(
                        self.execution_coordinator
                            .admit_finalized_wave(topology, wave),
                    );
                }
                actions
            }
            ProtocolEvent::FinalizedWaveVerified { wave, valid } => self
                .execution_coordinator
                .on_finalized_wave_verified(wave, valid),
            ProtocolEvent::ExecutionCertificateSignatureVerified { result } => self
                .execution_coordinator
                .on_certificate_verified(&self.topology_snapshot, result),
            ProtocolEvent::ExecutionCertificateAdmitted { certificate } => {
                let local_shard = self.topology_snapshot.local_shard();
                let mut actions = Vec::new();
                // If the EC is for a remote wave where we were a source, the
                // target shard's tx_outcomes acknowledge outbound batches we
                // sent. Surface the ACK to the outbound tracker.
                if certificate.shard_group_id() != local_shard
                    && certificate.wave_id().remote_shards().contains(&local_shard)
                {
                    actions.push(Action::Continuation(ProtocolEvent::OutboundEcObserved {
                        target_shard: certificate.shard_group_id(),
                        tx_outcomes: certificate.tx_outcomes().clone(),
                    }));
                }
                // Remote EC abort propagation may unlock local accumulators — re-scan.
                actions.extend(
                    self.execution_coordinator
                        .emit_vote_actions(&self.topology_snapshot),
                );
                actions
            }
            _ => unreachable!("non-execution event routed to handle_execution"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use hyperscale_core::{Action, ProtocolEvent, StateMachine};
    use hyperscale_types::{
        BlockHeight, Bls12381G2Signature, ExecutionCertificate, ExecutionOutcome,
        GlobalReceiptRoot, LocalTimestamp, ShardGroupId, SignerBitfield, TxHash, TxOutcome,
        Verified, WaveId, WeightedTimestamp,
    };

    use super::super::test_support::TestNode;
    use crate::{assert_no_emit, extract_one};

    fn make_ec(
        shard: ShardGroupId,
        remote_shards: BTreeSet<ShardGroupId>,
        height: BlockHeight,
        outcomes: Vec<TxOutcome>,
    ) -> Arc<Verified<ExecutionCertificate>> {
        let wave_id = WaveId::new(shard, height, remote_shards);
        Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            wave_id,
            WeightedTimestamp::from_millis(0),
            GlobalReceiptRoot::ZERO,
            outcomes,
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        )))
    }

    /// `ExecutionCertificateAdmitted` for a remote-shard EC where the
    /// wave's `remote_shards` includes local must surface an
    /// `OutboundEcObserved` continuation carrying the EC's `tx_outcomes`
    /// — that's how the outbound provision tracker learns its batches
    /// were ack'd.
    #[test]
    fn execution_certificate_admitted_emits_outbound_ec_continuation_when_we_were_a_source() {
        // 2-shard committee so local (0) ≠ EC shard (1).
        let TestNode { mut node, .. } = TestNode::builder().num_shards(2).build();

        let mut remote_shards = BTreeSet::new();
        remote_shards.insert(ShardGroupId::new(0));
        let ec = make_ec(
            ShardGroupId::new(1),
            remote_shards,
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
            assert_eq!(*target_shard, ShardGroupId::new(1));
            assert_eq!(tx_outcomes.len(), 1);
        } else {
            unreachable!()
        }
    }

    /// Same-shard EC: the EC's `shard_group_id` matches local, so the
    /// "remote ack" path doesn't apply and no `OutboundEcObserved`
    /// continuation must be emitted.
    #[test]
    fn execution_certificate_admitted_skips_continuation_for_same_shard_ec() {
        let TestNode { mut node, .. } = TestNode::new();

        let ec = make_ec(
            ShardGroupId::new(0),
            BTreeSet::new(),
            BlockHeight::new(1),
            vec![],
        );

        let actions = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::ExecutionCertificateAdmitted { certificate: ec },
        );

        assert_no_emit!(
            actions,
            Action::Continuation(ProtocolEvent::OutboundEcObserved { .. })
        );
    }

    /// Cross-shard EC where the wave's `remote_shards` does NOT include
    /// local: we were not a source for this wave, so no outbound ack to
    /// surface.
    #[test]
    fn execution_certificate_admitted_skips_continuation_when_local_not_a_source() {
        let TestNode { mut node, .. } = TestNode::builder().num_shards(3).build();

        // EC at shard 1, dependencies = {2}; local (0) is not in the set.
        let mut remote_shards = BTreeSet::new();
        remote_shards.insert(ShardGroupId::new(2));
        let ec = make_ec(
            ShardGroupId::new(1),
            remote_shards,
            BlockHeight::new(1),
            vec![],
        );

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
