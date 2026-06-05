//! Beacon-chain protocol-event dispatch.
//!
//! Routes each beacon-scoped [`ProtocolEvent`] to the matching method
//! on [`BeaconCoordinator`]. Mirrors the shape of [`super::shard`] /
//! [`super::execution`] / [`super::provisions`]: thin pass-through, no
//! cross-coordinator orchestration.
//!
//! Inline VRF verification on
//! [`ProtocolEvent::UnverifiedBeaconProposalReceived`] lifts the wire
//! `Verifiable<BeaconProposal>` to `Verified<BeaconProposal>` before
//! handing off to
//! [`BeaconCoordinator::on_beacon_proposal_received`]. The check is
//! synchronous (a single VRF verify under the proposer's pubkey) so
//! there's no dispatch round-trip — matches the pattern already used
//! inside [`BeaconCoordinator::on_beacon_proposal_fetched`].

use std::sync::Arc;

use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::{
    BeaconProposal, BeaconProposalVerifyContext, Epoch, ValidatorId, Verifiable,
};
use tracing::warn;

use super::NodeStateMachine;

impl NodeStateMachine {
    #[allow(clippy::too_many_lines)] // single dispatch over beacon ProtocolEvent variants
    pub(super) fn handle_beacon(&mut self, event: ProtocolEvent) -> Vec<Action> {
        match event {
            ProtocolEvent::UnverifiedPcVote1Received { view, vote } => {
                self.beacon_coordinator.on_pc_vote1_received(view, vote)
            }
            ProtocolEvent::UnverifiedPcVote2Received { view, vote } => {
                self.beacon_coordinator.on_pc_vote2_received(view, vote)
            }
            ProtocolEvent::UnverifiedPcVote3Received { view, vote } => {
                self.beacon_coordinator.on_pc_vote3_received(view, vote)
            }
            ProtocolEvent::VerifiedPcVote1Received { view, vote } => self
                .beacon_coordinator
                .on_verified_pc_vote1_received(view, vote),
            ProtocolEvent::VerifiedPcVote2Received { view, vote } => self
                .beacon_coordinator
                .on_verified_pc_vote2_received(view, vote),
            ProtocolEvent::VerifiedPcVote3Received { view, vote } => self
                .beacon_coordinator
                .on_verified_pc_vote3_received(view, vote),
            ProtocolEvent::SpcNewViewReceived { from, proposal } => self
                .beacon_coordinator
                .on_spc_new_view_received(from, proposal),
            ProtocolEvent::SpcNewCommitReceived { from, msg } => self
                .beacon_coordinator
                .on_spc_new_commit_received(from, msg),
            ProtocolEvent::UnverifiedSpcEmptyViewReceived { msg } => self
                .beacon_coordinator
                .on_unverified_spc_empty_view_received(msg),
            ProtocolEvent::VerifiedSpcEmptyViewReceived { msg } => self
                .beacon_coordinator
                .on_verified_spc_empty_view_received(msg),
            ProtocolEvent::BeaconBlockReceived { block } => {
                self.beacon_coordinator.on_beacon_block_received(block)
            }
            ProtocolEvent::UnverifiedBeaconProposalReceived {
                from,
                epoch,
                proposal,
            } => self.dispatch_unverified_beacon_proposal(from, epoch, proposal),
            ProtocolEvent::VerifiedBeaconProposalReceived {
                from,
                epoch,
                proposal,
            } => self
                .beacon_coordinator
                .on_beacon_proposal_received(from, epoch, proposal),
            ProtocolEvent::UnverifiedSkipRequestReceived { request } => self
                .beacon_coordinator
                .on_unverified_skip_request_received(request),
            ProtocolEvent::VerifiedSkipRequestReceived { request } => self
                .beacon_coordinator
                .on_verified_skip_request_received(request),
            ProtocolEvent::SkipCertReceived { cert } => {
                self.beacon_coordinator.on_skip_cert_received(cert)
            }
            ProtocolEvent::ShardWitnessesReceived {
                shard_id,
                witnesses,
            } => self
                .beacon_coordinator
                .on_shard_witnesses_received(shard_id, witnesses),
            ProtocolEvent::BeaconProposalFetched {
                epoch,
                validator,
                proposal,
            } => self
                .beacon_coordinator
                .on_beacon_proposal_fetched(epoch, validator, proposal),
            ProtocolEvent::BeaconBlockVerified { result } => {
                self.beacon_coordinator.on_beacon_block_verified(result)
            }
            ProtocolEvent::SkipRequestVerified {
                anchor,
                epoch_to_skip,
                signer,
                result,
            } => self.beacon_coordinator.on_skip_request_verified(
                anchor,
                epoch_to_skip,
                signer,
                result,
            ),
            ProtocolEvent::PcVote1Verified {
                epoch,
                view,
                signer,
                result,
            } => self
                .beacon_coordinator
                .on_pc_vote1_verified(epoch, view, signer, result),
            ProtocolEvent::PcVote2Verified {
                epoch,
                view,
                signer,
                result,
            } => self
                .beacon_coordinator
                .on_pc_vote2_verified(epoch, view, signer, result),
            ProtocolEvent::PcVote3Verified {
                epoch,
                view,
                signer,
                result,
            } => self
                .beacon_coordinator
                .on_pc_vote3_verified(epoch, view, signer, result),
            ProtocolEvent::SpcNewViewVerified {
                epoch,
                from,
                view,
                result,
            } => self
                .beacon_coordinator
                .on_spc_new_view_verified(epoch, from, view, result),
            ProtocolEvent::SpcNewCommitVerified {
                epoch,
                from,
                view,
                result,
            } => self
                .beacon_coordinator
                .on_spc_new_commit_verified(epoch, from, view, result),
            ProtocolEvent::SpcEmptyViewVerified {
                epoch,
                from,
                view,
                result,
            } => self
                .beacon_coordinator
                .on_spc_empty_view_verified(epoch, from, view, result),
            ProtocolEvent::BeaconCommitteeStartTimer => {
                self.beacon_coordinator.on_beacon_committee_start_timer()
            }
            ProtocolEvent::BeaconSkipTimer => self.beacon_coordinator.on_beacon_skip_timer(),
            ProtocolEvent::BeaconSpcViewTimer => self.beacon_coordinator.on_beacon_spc_view_timer(),
            ProtocolEvent::BeaconBlockPersisted { .. } => {
                // Beacon advanced an epoch — replay any cross-shard artifacts
                // buffered because their committee epoch wasn't yet in the
                // schedule (remote headers, ECs, finalized waves).
                let mut actions = self
                    .remote_headers_coordinator
                    .on_beacon_block_persisted(self.beacon_coordinator.topology_schedule());
                actions.extend(
                    self.execution_coordinator
                        .on_beacon_block_persisted(self.beacon_coordinator.topology_schedule()),
                );
                actions
            }
            ProtocolEvent::BeaconBlockSyncReadyToApply { block } => self
                .beacon_coordinator
                .on_beacon_block_sync_ready_to_apply(block),
            _ => unreachable!("handle_beacon called with non-beacon ProtocolEvent"),
        }
    }

    /// VRF-verify an inbound `BeaconProposal` against the sender's
    /// pubkey, then hand the resulting `Verified` to the coordinator.
    /// Drops with a warn if the sender isn't in `BeaconState.validators`
    /// or the VRF reveal fails.
    fn dispatch_unverified_beacon_proposal(
        &mut self,
        from: ValidatorId,
        epoch: Epoch,
        proposal: Arc<Verifiable<BeaconProposal>>,
    ) -> Vec<Action> {
        let Some(record) = self
            .beacon_coordinator
            .current_state()
            .validators
            .get(&from)
        else {
            warn!(
                ?from,
                "UnverifiedBeaconProposalReceived from validator not in BeaconState — dropping",
            );
            return Vec::new();
        };
        let ctx = BeaconProposalVerifyContext {
            network: self.beacon_coordinator.network_definition(),
            epoch,
            sender_pk: record.pubkey,
        };
        match Arc::unwrap_or_clone(proposal).upgrade(&ctx) {
            Ok(verified) => {
                self.beacon_coordinator
                    .on_beacon_proposal_received(from, epoch, Arc::new(verified))
            }
            Err((_, err)) => {
                warn!(
                    ?from,
                    epoch = epoch.inner(),
                    ?err,
                    "UnverifiedBeaconProposalReceived VRF verification failed — dropping",
                );
                Vec::new()
            }
        }
    }
}
