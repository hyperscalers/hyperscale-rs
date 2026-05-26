//! Delegated-action handlers for beacon-owned [`Action`] variants.
//!
//! [`handle_action`] runs off the `io_loop` thread on the Consensus
//! dispatch pool; results return to the state machine via
//! `ctx.notify(ProtocolEvent::*)`. The node's dispatcher routes any
//! [`ActionOwner::Beacon`](hyperscale_core::ActionOwner) action here
//! and unreachable-panics on non-beacon variants — mirrors
//! `hyperscale_shard::action_handlers::handle_action`.

use std::sync::Arc;

use hyperscale_core::{Action, ActionContext, ProtocolEvent};
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::notification::{
    BeaconProposalNotification, PcVote1Notification, PcVote2Notification, PcVote3Notification,
    SpcEmptyViewMsgNotification, SpcNewCommitNotification, SpcNewViewNotification,
};
use hyperscale_types::{
    BeaconProposal, SpcHighTriple, SpcMessage, SpcProposalObject, VpcMsgPayload, pc_context,
    spc_context, vrf_sign,
};
use tracing::warn;

use crate::pc::{sign_vote1, sign_vote2, sign_vote3};
use crate::spc::sign_empty_view_msg;

/// Dispatch a beacon-owned [`Action`] on the consensus pool. Panics on
/// non-beacon variants — the node's owner-keyed dispatch is the gate.
#[allow(clippy::too_many_lines)] // single dispatch over beacon-owned Action variants
#[allow(clippy::missing_panics_doc)] // basic_encode of typed SBOR enums is infallible
pub fn handle_action<S, N>(action: Action, ctx: &ActionContext<'_, S, N>)
where
    S: ShardStorage,
    N: Network,
{
    let me = ctx.topology_snapshot.local_validator_id();
    let network = ctx.topology_snapshot.network();
    match action {
        Action::SignAndBroadcastPcVote1 {
            epoch,
            view,
            v_in,
            recipients,
        } => {
            let pc_ctx = pc_context(&spc_context(epoch), view);
            let vote = sign_vote1(ctx.signing_key, me, network, &pc_ctx, v_in);
            ctx.network
                .notify(&recipients, &PcVote1Notification::new(vote.clone()));
            let payload = VpcMsgPayload::Vote1 { view, vote };
            let bytes = payload.encode_bytes();
            ctx.notify_protocol(ProtocolEvent::PcVoteReceived {
                from: me,
                payload: bytes,
            });
        }
        Action::SignAndBroadcastPcVote2 {
            epoch,
            view,
            qc1,
            recipients,
        } => {
            let pc_ctx = pc_context(&spc_context(epoch), view);
            let vote = sign_vote2(ctx.signing_key, me, network, &pc_ctx, *qc1);
            ctx.network
                .notify(&recipients, &PcVote2Notification::new(vote.clone()));
            let payload = VpcMsgPayload::Vote2 {
                view,
                vote: Box::new(vote),
            };
            let bytes = payload.encode_bytes();
            ctx.notify_protocol(ProtocolEvent::PcVoteReceived {
                from: me,
                payload: bytes,
            });
        }
        Action::SignAndBroadcastPcVote3 {
            epoch,
            view,
            qc2,
            recipients,
        } => {
            let pc_ctx = pc_context(&spc_context(epoch), view);
            let vote = sign_vote3(ctx.signing_key, me, network, &pc_ctx, *qc2);
            ctx.network
                .notify(&recipients, &PcVote3Notification::new(vote.clone()));
            let payload = VpcMsgPayload::Vote3 {
                view,
                vote: Box::new(vote),
            };
            let bytes = payload.encode_bytes();
            ctx.notify_protocol(ProtocolEvent::PcVoteReceived {
                from: me,
                payload: bytes,
            });
        }
        Action::SignAndBroadcastEmptyView {
            epoch,
            view,
            reported,
            recipients,
        } => {
            let spc_ctx = spc_context(epoch);
            let msg = sign_empty_view_msg(ctx.signing_key, me, network, &spc_ctx, view, *reported);
            ctx.network
                .notify(&recipients, &SpcEmptyViewMsgNotification::new(msg.clone()));
            let wire = SpcMessage::EmptyView(Box::new(msg));
            let bytes = wire.encode_bytes();
            ctx.notify_protocol(ProtocolEvent::SpcMessageReceived {
                from: me,
                payload: bytes,
            });
        }
        Action::BroadcastSpcNewView {
            epoch: _,
            view,
            cert,
            recipients,
        } => {
            let proposal = SpcProposalObject { view, cert: *cert };
            ctx.network
                .notify(&recipients, &SpcNewViewNotification::new(proposal));
        }
        Action::BroadcastSpcNewCommit {
            epoch: _,
            view,
            value,
            proof,
            recipients,
        } => {
            let triple = SpcHighTriple {
                view,
                value,
                proof: *proof,
            };
            ctx.network
                .notify(&recipients, &SpcNewCommitNotification::new(triple));
        }
        Action::BuildAndBroadcastBeaconProposal {
            epoch,
            witnesses,
            recipients,
        } => {
            let (vrf_output, vrf_proof) = vrf_sign(ctx.signing_key, network, epoch);
            let proposal = Arc::new(BeaconProposal::new(witnesses, vrf_output, vrf_proof));
            ctx.network.notify(
                &recipients,
                &BeaconProposalNotification::new(me, epoch, Arc::clone(&proposal)),
            );
            ctx.notify_protocol(ProtocolEvent::BeaconProposalReceived {
                from: me,
                epoch,
                proposal,
            });
        }
        Action::BroadcastBeaconBlock { block } => {
            warn!(epoch = block.epoch().inner(), "BroadcastBeaconBlock");
        }
        Action::BroadcastSkipRequest {
            request,
            recipients: _,
        } => {
            warn!(
                epoch_to_skip = request.epoch_to_skip().inner(),
                signer = ?request.signer(),
                "BroadcastSkipRequest",
            );
        }
        Action::BroadcastSkipCert {
            cert,
            recipients: _,
        } => {
            warn!(
                epoch_to_skip = cert.epoch_to_skip().inner(),
                signer_count = cert.signer_count(),
                "BroadcastSkipCert",
            );
        }
        Action::FetchShardWitnesses {
            shard_id,
            committed_block_hash: _,
            leaf_indices,
            peers: _,
        } => {
            warn!(
                shard = shard_id.inner(),
                leaves = leaf_indices.len(),
                "FetchShardWitnesses",
            );
        }
        Action::VerifyBeaconRoot {
            kind,
            key: _,
            payload: _,
        } => {
            warn!(kind = ?kind, "VerifyBeaconRoot");
        }
        _ => unreachable!("hyperscale_beacon::handle_action called with non-beacon action"),
    }
}
