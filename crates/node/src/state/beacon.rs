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
use super::participation::ShardParticipation;

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
            ProtocolEvent::BeaconSpcInputDwellTimer => {
                self.beacon_coordinator.on_spc_input_dwell_timer()
            }
            ProtocolEvent::BeaconBlockPersisted { .. } => {
                // Beacon advanced an epoch — drive the shard coordinators to
                // replay buffered cross-shard artifacts (remote headers, ECs,
                // finalized waves) and acquire any newly-attested settled-waves
                // set the fence needs. Skipped for a vnode that only follows the
                // beacon.
                self.with_shard(ShardParticipation::on_beacon_block_persisted)
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

#[cfg(test)]
mod tests {
    use hyperscale_core::{Action, ProtocolEvent, StateMachine};
    use hyperscale_types::{Epoch, LocalTimestamp, Round};

    use super::super::test_support::TestNode;

    /// A proposer whose committee lookup stalls on a not-yet-committed epoch
    /// has no retry signal other than the beacon adopting that epoch, so
    /// `BeaconBlockPersisted` must latch a proposal retry for the
    /// post-dispatch hook to turn into `try_propose`. Without it the
    /// view-change timer fires first, the height moves to a later round, and
    /// the round-contiguous commit rule never sees consecutive rounds while
    /// the beacon trails. End-to-end on a leader, the event must surface a
    /// `BuildProposal` action.
    #[test]
    fn beacon_block_persisted_drives_proposal_through_post_dispatch_hook() {
        // Rounds increase per block, so height 1 is round 1:
        // proposer_for(r=1) = committee[1 % 4] = ValidatorId::new(1).
        let TestNode { mut node, .. } = TestNode::builder().local_idx(1).build();
        assert!(
            node.topology_snapshot()
                .proposer_for(node.shard_id(), Round::new(1))
                == node.validator_id(),
            "local must be the height-1 proposer for this test",
        );

        let actions = node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::BeaconBlockPersisted {
                epoch: Epoch::GENESIS,
            },
        );

        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BuildProposal { .. })),
            "expected BuildProposal after BeaconBlockPersisted on a leader; got {actions:?}",
        );
    }
}
