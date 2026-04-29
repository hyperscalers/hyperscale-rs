//! Execution-flow dispatch arms.
//!
//! Covers wave-based voting (votes received, aggregated, certificate
//! verified) and the engine results path (`ExecutionBatchCompleted`).
//!
//! Cross-shard EC admission has a quirk: if an admitted EC names the local
//! shard among `wave_id.remote_shards`, that EC's `tx_outcomes` ack the
//! outbound batches we sent — the admission arm captures that ACK and emits
//! a follow-up `OutboundEcObserved` to feed the outbound provision tracker.

use super::NodeStateMachine;
use hyperscale_core::{Action, ProtocolEvent};

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
                let mut actions =
                    self.execution
                        .on_execution_batch_completed(&wave_id, results, tx_outcomes);
                actions.extend(self.execution.emit_vote_actions(self.topology.snapshot()));
                actions
            }
            ProtocolEvent::ExecutionVoteReceived { vote } => self
                .execution
                .on_execution_vote(self.topology.snapshot(), vote),
            ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                wave_id,
                block_hash,
                verified_votes,
            } => self.execution.on_votes_verified(
                self.topology.snapshot(),
                wave_id,
                block_hash,
                verified_votes,
            ),
            ProtocolEvent::ExecutionCertificateAggregated {
                wave_id,
                certificate,
            } => self.execution.on_certificate_aggregated(
                self.topology.snapshot(),
                &wave_id,
                certificate,
            ),
            ProtocolEvent::ExecutionCertificatesReceived { certificates } => {
                let topology = self.topology.snapshot();
                let mut actions = Vec::new();
                for cert in certificates {
                    actions.extend(self.execution.on_wave_certificate(topology, cert));
                }
                actions
            }
            ProtocolEvent::FinalizedWavesReceived { waves } => {
                let mut actions = Vec::new();
                for wave in waves {
                    actions.extend(self.execution.admit_finalized_wave(wave));
                }
                actions
            }
            ProtocolEvent::ExecutionCertificateSignatureVerified { certificate, valid } => self
                .execution
                .on_certificate_verified(self.topology.snapshot(), certificate, valid),
            ProtocolEvent::ExecutionCertificateAdmitted { certificate } => {
                let local_shard = self.topology.snapshot().local_shard();
                let mut actions = Vec::new();
                // If the EC is for a remote wave where we were a source, the
                // target shard's tx_outcomes acknowledge outbound batches we
                // sent. Surface the ACK to the outbound tracker.
                if certificate.shard_group_id() != local_shard
                    && certificate.wave_id.remote_shards.contains(&local_shard)
                {
                    actions.push(Action::Continuation(ProtocolEvent::OutboundEcObserved {
                        target_shard: certificate.shard_group_id(),
                        tx_outcomes: certificate.tx_outcomes.clone(),
                    }));
                }
                // Remote EC abort propagation may unlock local accumulators — re-scan.
                actions.extend(self.execution.emit_vote_actions(self.topology.snapshot()));
                actions
            }
            _ => unreachable!("non-execution event routed to handle_execution"),
        }
    }
}
