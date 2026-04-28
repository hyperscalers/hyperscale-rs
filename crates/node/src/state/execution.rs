//! Execution-flow dispatch arms.
//!
//! Covers wave-based voting (votes received, aggregated, certificate
//! verified) and the engine results path (`ExecutionBatchCompleted`).
//! `WaveCompleted` re-triggers proposal building; `ExecutionCertificateAdmitted`
//! is a pure admission signal drained by `IoLoop`.
//!
//! Cross-shard EC verification has a quirk: if a remote target's EC names
//! the local shard among `wave_id.remote_shards`, that EC's `tx_outcomes`
//! ack the outbound batches we sent — the verification arm captures that
//! ACK and emits a follow-up `OutboundEcObserved` to feed the outbound
//! provision tracker.

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
            ProtocolEvent::ExecutionCertificateSignatureVerified { certificate, valid } => {
                // If the EC is for a remote wave where we were a source, the
                // target shard's tx_outcomes acknowledge outbound batches we
                // sent. Capture the ACK signal before the cert is consumed.
                let local_shard = self.topology.snapshot().local_shard();
                let outbound_ack = if valid
                    && certificate.shard_group_id() != local_shard
                    && certificate.wave_id.remote_shards.contains(&local_shard)
                {
                    Some((
                        certificate.shard_group_id(),
                        certificate.tx_outcomes.clone(),
                    ))
                } else {
                    None
                };

                let mut actions = self.execution.on_certificate_verified(
                    self.topology.snapshot(),
                    certificate,
                    valid,
                );
                if let Some((target_shard, tx_outcomes)) = outbound_ack {
                    actions.push(Action::Continuation(ProtocolEvent::OutboundEcObserved {
                        target_shard,
                        tx_outcomes,
                    }));
                }
                // Remote EC abort propagation may unlock local accumulators — re-scan.
                actions.extend(self.execution.emit_vote_actions(self.topology.snapshot()));
                actions
            }
            ProtocolEvent::WaveCompleted { .. } => {
                // New finalized wave available — signal for event-driven proposal.
                vec![Action::Continuation(ProtocolEvent::ContentAvailable)]
            }
            // Pure admission signal — `io_loop`'s `Continuation` interception
            // arm drains the exec-cert fetch protocol; nothing for the state
            // machine to do here.
            ProtocolEvent::ExecutionCertificateAdmitted { .. } => vec![],
            _ => unreachable!("non-execution event routed to handle_execution"),
        }
    }

    /// Hand a delivered execution certificate to the canonical EC store.
    /// Called directly from `io_loop` for both fetch responses and gossip-
    /// delivered cert batches (post sender-sig check). Each cert flows through
    /// `ExecutionCoordinator::on_wave_certificate`, which emits
    /// `Continuation(ProtocolEvent::ExecutionCertificateAdmitted)` so the
    /// fetch protocol is drained per wave.
    pub fn on_execution_certs_received(
        &mut self,
        certs: Vec<hyperscale_types::ExecutionCertificate>,
    ) -> Vec<Action> {
        let topology = self.topology.snapshot();
        let mut actions = Vec::new();
        for cert in certs {
            actions.extend(self.execution.on_wave_certificate(topology, cert));
        }
        actions
    }
}
