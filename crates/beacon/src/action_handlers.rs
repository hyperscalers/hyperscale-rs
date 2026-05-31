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
use hyperscale_types::network::gossip::beacon::{
    BeaconBlockGossip, SkipCertGossip, SkipRequestGossip,
};
use hyperscale_types::network::notification::{
    BeaconProposalNotification, PcVote1Notification, PcVote2Notification, PcVote3Notification,
    SpcEmptyViewMsgNotification, SpcNewCommitNotification, SpcNewViewNotification,
};
use hyperscale_types::{
    BeaconProposal, CertifiedBeaconBlockVerifyContext, DOMAIN_SPC_NEW_COMMIT, DOMAIN_SPC_NEW_VIEW,
    PcVote1, PcVote2, PcVote3, PcVoteVerifyContext, SkipRequest, SkipVerifyContext,
    SpcEmptyViewMsg, SpcVerifyContext, Verifiable, Verified, pc_context, spc_context,
    spc_relay_signing_message,
};

/// Dispatch a beacon-owned [`Action`] on the consensus pool. Panics on
/// non-beacon variants — the node's owner-keyed dispatch is the gate.
#[allow(clippy::too_many_lines)] // single dispatch over beacon-owned Action variants
pub fn handle_action<S, N>(action: Action, ctx: &ActionContext<'_, S, N>)
where
    S: ShardStorage,
    N: Network,
{
    let me = ctx.me;
    let network = ctx.topology_snapshot.network();
    match action {
        Action::SignAndBroadcastPcVote1 {
            epoch,
            view,
            v_in,
            recipients,
        } => {
            let pc_ctx = pc_context(&spc_context(epoch), view);
            let verified =
                Verified::<PcVote1>::sign_local(ctx.signing_key, me, network, &pc_ctx, v_in);
            ctx.network.notify(
                &recipients,
                &PcVote1Notification::new(view, Arc::new(Verifiable::from(verified.clone()))),
            );
            ctx.notify_protocol(ProtocolEvent::VerifiedPcVote1Received {
                from: me,
                view,
                vote: verified,
            });
        }
        Action::SignAndBroadcastPcVote2 {
            epoch,
            view,
            qc1,
            recipients,
        } => {
            let pc_ctx = pc_context(&spc_context(epoch), view);
            let verified =
                Verified::<PcVote2>::sign_local(ctx.signing_key, me, network, &pc_ctx, *qc1);
            ctx.network.notify(
                &recipients,
                &PcVote2Notification::new(view, Arc::new(Verifiable::from(verified.clone()))),
            );
            ctx.notify_protocol(ProtocolEvent::VerifiedPcVote2Received {
                from: me,
                view,
                vote: Box::new(verified),
            });
        }
        Action::SignAndBroadcastPcVote3 {
            epoch,
            view,
            qc2,
            recipients,
        } => {
            let pc_ctx = pc_context(&spc_context(epoch), view);
            let verified =
                Verified::<PcVote3>::sign_local(ctx.signing_key, me, network, &pc_ctx, *qc2);
            ctx.network.notify(
                &recipients,
                &PcVote3Notification::new(view, Arc::new(Verifiable::from(verified.clone()))),
            );
            ctx.notify_protocol(ProtocolEvent::VerifiedPcVote3Received {
                from: me,
                view,
                vote: Box::new(verified),
            });
        }
        Action::SignAndBroadcastEmptyView {
            epoch,
            view,
            reported,
            recipients,
        } => {
            let spc_ctx = spc_context(epoch);
            let verified = Verified::<SpcEmptyViewMsg>::sign_local(
                ctx.signing_key,
                me,
                network,
                &spc_ctx,
                view,
                *reported,
            );
            ctx.network.notify(
                &recipients,
                &SpcEmptyViewMsgNotification::new(Arc::new(Verifiable::from(verified.clone()))),
            );
            ctx.notify_protocol(ProtocolEvent::VerifiedSpcEmptyViewReceived {
                msg: Box::new(verified),
            });
        }
        Action::BroadcastSpcNewView {
            epoch,
            proposal,
            recipients,
        } => {
            let view = proposal.view;
            let proposal_hash = proposal.hash();
            let signing_msg = spc_relay_signing_message(
                network,
                DOMAIN_SPC_NEW_VIEW,
                epoch,
                view,
                &proposal_hash,
            );
            let sig = ctx.signing_key.sign_v1(&signing_msg);
            ctx.network.notify(
                &recipients,
                &SpcNewViewNotification::new(epoch, me, sig, Arc::new(Verifiable::from(*proposal))),
            );
        }
        Action::BroadcastSpcNewCommit {
            epoch,
            msg,
            recipients,
        } => {
            let view = msg.view;
            let msg_hash = msg.hash();
            let signing_msg =
                spc_relay_signing_message(network, DOMAIN_SPC_NEW_COMMIT, epoch, view, &msg_hash);
            let sig = ctx.signing_key.sign_v1(&signing_msg);
            ctx.network.notify(
                &recipients,
                &SpcNewCommitNotification::new(epoch, me, sig, Arc::new(Verifiable::from(*msg))),
            );
        }
        Action::BuildAndBroadcastBeaconProposal {
            epoch,
            witnesses,
            recipients,
        } => {
            let verified =
                Verified::<BeaconProposal>::sign_local(ctx.signing_key, network, epoch, witnesses);
            let proposal = Arc::new(verified);
            ctx.network.notify(
                &recipients,
                &BeaconProposalNotification::new(
                    me,
                    epoch,
                    Arc::new(Verifiable::from((*proposal).clone())),
                ),
            );
            ctx.notify_protocol(ProtocolEvent::VerifiedBeaconProposalReceived {
                from: me,
                epoch,
                proposal,
            });
        }
        Action::BroadcastBeaconBlock { block } => {
            ctx.network
                .broadcast_global(&BeaconBlockGossip::new(Arc::new(Verifiable::from(
                    Arc::unwrap_or_clone(block),
                ))));
        }
        Action::BroadcastSkipRequest {
            epoch_to_skip,
            anchor,
        } => {
            let verified = Verified::<SkipRequest>::sign_local(
                ctx.signing_key,
                me,
                network,
                anchor,
                epoch_to_skip,
            );
            let request = Arc::new(verified);
            ctx.network
                .broadcast_global(&SkipRequestGossip::new(Arc::new(Verifiable::from(
                    (*request).clone(),
                ))));
            ctx.notify_protocol(ProtocolEvent::VerifiedSkipRequestReceived { request });
        }
        Action::BroadcastSkipCert { cert } => {
            ctx.network
                .broadcast_global(&SkipCertGossip::new(Arc::new(Verifiable::from(
                    (*cert).clone(),
                ))));
        }
        Action::VerifyBeaconBlock {
            block,
            signers,
            equivocation_signers,
        } => {
            let result = Arc::unwrap_or_clone(block)
                .upgrade(&CertifiedBeaconBlockVerifyContext {
                    network,
                    signers: &signers,
                    equivocation_signers: &equivocation_signers,
                })
                .map(Arc::new)
                .map_err(|(_, e)| e);
            ctx.notify_protocol(ProtocolEvent::BeaconBlockVerified { result });
        }
        Action::VerifySkipRequest { request, signers } => {
            let result = (*request)
                .upgrade(&SkipVerifyContext {
                    network,
                    active_pool: &signers,
                })
                .map_err(|(_, e)| e);
            ctx.notify_protocol(ProtocolEvent::SkipRequestVerified { result });
        }
        Action::VerifyPcVote1 {
            epoch,
            view,
            vote,
            committee,
        } => {
            let pc_ctx = pc_context(&spc_context(epoch), view);
            let signer = vote.validator();
            let result = vote.upgrade(&PcVoteVerifyContext {
                network,
                pc_ctx: &pc_ctx,
                committee: &committee,
            });
            ctx.notify_protocol(ProtocolEvent::PcVote1Verified {
                epoch,
                view,
                signer,
                result: result.map_err(|(_, e)| e),
            });
        }
        Action::VerifyPcVote2 {
            epoch,
            view,
            vote,
            committee,
        } => {
            let pc_ctx = pc_context(&spc_context(epoch), view);
            let signer = vote.validator();
            let result = (*vote).upgrade(&PcVoteVerifyContext {
                network,
                pc_ctx: &pc_ctx,
                committee: &committee,
            });
            ctx.notify_protocol(ProtocolEvent::PcVote2Verified {
                epoch,
                view,
                signer,
                result: result.map_err(|(_, e)| e),
            });
        }
        Action::VerifyPcVote3 {
            epoch,
            view,
            vote,
            committee,
        } => {
            let pc_ctx = pc_context(&spc_context(epoch), view);
            let signer = vote.validator();
            let result = (*vote).upgrade(&PcVoteVerifyContext {
                network,
                pc_ctx: &pc_ctx,
                committee: &committee,
            });
            ctx.notify_protocol(ProtocolEvent::PcVote3Verified {
                epoch,
                view,
                signer,
                result: result.map_err(|(_, e)| e),
            });
        }
        Action::VerifySpcNewView {
            epoch,
            from,
            proposal,
            committee,
        } => {
            let spc_ctx = spc_context(epoch);
            let view = proposal.view;
            let result = (*proposal).upgrade(&SpcVerifyContext {
                network,
                spc_ctx: &spc_ctx,
                committee: &committee,
            });
            ctx.notify_protocol(ProtocolEvent::SpcNewViewVerified {
                epoch,
                from,
                view,
                result: result.map_err(|(_, e)| e),
            });
        }
        Action::VerifySpcNewCommit {
            epoch,
            from,
            msg,
            committee,
        } => {
            let spc_ctx = spc_context(epoch);
            let view = msg.view;
            let result = (*msg).upgrade(&SpcVerifyContext {
                network,
                spc_ctx: &spc_ctx,
                committee: &committee,
            });
            ctx.notify_protocol(ProtocolEvent::SpcNewCommitVerified {
                epoch,
                from,
                view,
                result: result.map_err(|(_, e)| e),
            });
        }
        Action::VerifySpcEmptyView {
            epoch,
            msg,
            committee,
        } => {
            let spc_ctx = spc_context(epoch);
            let from = msg.signer;
            let view = msg.view;
            let result = (*msg).upgrade(&SpcVerifyContext {
                network,
                spc_ctx: &spc_ctx,
                committee: &committee,
            });
            ctx.notify_protocol(ProtocolEvent::SpcEmptyViewVerified {
                epoch,
                from,
                view,
                result: result.map_err(|(_, e)| e),
            });
        }
        _ => unreachable!("hyperscale_beacon::handle_action called with non-beacon action"),
    }
}
