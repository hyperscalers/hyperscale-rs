//! Delegated-action handlers for beacon-owned [`Action`] variants.
//!
//! [`handle_action`] runs off the `io_loop` thread on the Consensus
//! dispatch pool for seated vnodes, and inline on the follower pool's
//! driver for shard-less ones; results return to the state machine via
//! `ctx.notify(ProtocolEvent::*)`. The node's dispatchers route any
//! [`ActionOwner::Beacon`](hyperscale_core::ActionOwner) action here
//! and unreachable-panic on non-beacon variants — mirrors
//! `hyperscale_shard::action_handlers::handle_action`. The context is
//! the storage-free [`BeaconActionContext`], so both dispatch sites can
//! build it.

use std::sync::Arc;

use hyperscale_core::{Action, BeaconActionContext, ProtocolEvent};
use hyperscale_network::Network;
use hyperscale_types::network::gossip::beacon::{
    BeaconBlockGossip, BeaconCandidateGossip, RatifyVoteGossip,
};
use hyperscale_types::network::notification::{
    BeaconProposalNotification, PcVote1Notification, PcVote2Notification, PcVote3Notification,
    SpcEmptyViewMsgNotification, SpcNewCommitNotification, SpcNewViewNotification,
};
use hyperscale_types::{
    BeaconProposal, CandidateVerifyContext, CertifiedBeaconBlockVerifyContext, PcScope, PcVote1,
    PcVote2, PcVote3, PcVoteVerifyContext, RatifyVerifyContext, RatifyVote, SpcEmptyViewMsg,
    SpcRelayKind, SpcRelayMessage, SpcVerifyContext, Verifiable, Verified, signed_bytes,
};

/// Dispatch a beacon-owned [`Action`]. Panics on non-beacon variants —
/// the node's owner-keyed dispatch is the gate.
#[allow(clippy::too_many_lines)] // single dispatch over beacon-owned Action variants
pub fn handle_action<N>(action: Action, ctx: &BeaconActionContext<'_, N>)
where
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
            let instance = PcScope { epoch, view };
            let Ok(verified) =
                Verified::<PcVote1>::sign_local(ctx.signer.as_ref(), me, network, instance, v_in)
            else {
                tracing::error!(?view, "cannot sign PC vote1; abstaining");
                return;
            };
            ctx.network.notify(
                &recipients,
                &PcVote1Notification::new(view, Arc::new(Verifiable::from(verified.clone()))),
            );
            ctx.notify_protocol(ProtocolEvent::VerifiedPcVote1Received {
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
            let instance = PcScope { epoch, view };
            let Ok(verified) =
                Verified::<PcVote2>::sign_local(ctx.signer.as_ref(), me, network, instance, *qc1)
            else {
                tracing::error!(?view, "cannot sign PC vote2; abstaining");
                return;
            };
            ctx.network.notify(
                &recipients,
                &PcVote2Notification::new(view, Arc::new(Verifiable::from(verified.clone()))),
            );
            ctx.notify_protocol(ProtocolEvent::VerifiedPcVote2Received {
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
            let instance = PcScope { epoch, view };
            let Ok(verified) =
                Verified::<PcVote3>::sign_local(ctx.signer.as_ref(), me, network, instance, *qc2)
            else {
                tracing::error!(?view, "cannot sign PC vote3; abstaining");
                return;
            };
            ctx.network.notify(
                &recipients,
                &PcVote3Notification::new(view, Arc::new(Verifiable::from(verified.clone()))),
            );
            ctx.notify_protocol(ProtocolEvent::VerifiedPcVote3Received {
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
            let Ok(verified) = Verified::<SpcEmptyViewMsg>::sign_local(
                ctx.signer.as_ref(),
                me,
                network,
                epoch,
                view,
                *reported,
            ) else {
                tracing::error!(?view, "cannot sign empty-view attestation; abstaining");
                return;
            };
            ctx.network.notify(
                &recipients,
                &SpcEmptyViewMsgNotification::new(
                    epoch,
                    Arc::new(Verifiable::from(verified.clone())),
                ),
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
            let signing_msg = signed_bytes(
                &SpcRelayMessage {
                    kind: SpcRelayKind::NewView,
                    epoch,
                    view,
                    content_hash: proposal_hash,
                },
                network,
            );
            let Ok(sig) = ctx.signer.sign(&signing_msg) else {
                tracing::error!(?view, "cannot sign SPC new-view relay; skipping");
                return;
            };
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
            let signing_msg = signed_bytes(
                &SpcRelayMessage {
                    kind: SpcRelayKind::NewCommit,
                    epoch,
                    view,
                    content_hash: msg_hash,
                },
                network,
            );
            let Ok(sig) = ctx.signer.sign(&signing_msg) else {
                tracing::error!(?view, "cannot sign SPC new-commit relay; skipping");
                return;
            };
            ctx.network.notify(
                &recipients,
                &SpcNewCommitNotification::new(epoch, me, sig, Arc::new(Verifiable::from(*msg))),
            );
        }
        Action::BuildAndBroadcastBeaconProposal {
            epoch,
            boundary_qcs,
            equivocations,
            fork_proofs,
            vote_equivocations,
            recipients,
        } => {
            let Ok(verified) = Verified::<BeaconProposal>::sign_local(
                ctx.signer.as_ref(),
                network,
                epoch,
                boundary_qcs,
                equivocations,
                fork_proofs,
                vote_equivocations,
            ) else {
                tracing::error!(?epoch, "cannot sign beacon proposal; skipping");
                return;
            };
            let proposal = Arc::new(verified);
            (ctx.cache_beacon_proposal)(me, epoch, Arc::clone(&proposal));
            ctx.network.notify(
                &recipients,
                &BeaconProposalNotification::new(
                    me,
                    epoch,
                    Arc::new(Verifiable::from((*proposal).clone())),
                ),
            );
            ctx.notify_protocol(ProtocolEvent::BeaconProposalReceived {
                from: me,
                epoch,
                proposal: Arc::new(Verifiable::from(Arc::unwrap_or_clone(proposal))),
            });
        }
        Action::BroadcastBeaconBlock { block } => {
            ctx.network
                .broadcast_global(&BeaconBlockGossip::new(Arc::new(Verifiable::from(
                    Arc::unwrap_or_clone(block),
                ))));
        }
        Action::SignAndBroadcastRatifyVote {
            anchor,
            epoch,
            round,
            phase,
            block_hash,
        } => {
            // The (round, phase) slot this vote consumes must be durable
            // before the signature exists — a crash between them costs
            // at most an abstention, never a double-vote or a lost lock.
            ctx.ratify_registers
                .record_ratify_vote(me, epoch, round, phase, block_hash);
            let Ok(verified) = Verified::<RatifyVote>::sign_local(
                ctx.signer.as_ref(),
                me,
                network,
                anchor,
                epoch,
                round,
                phase,
                block_hash,
            ) else {
                tracing::error!(?epoch, ?round, "cannot sign ratify vote; abstaining");
                return;
            };
            let vote = Arc::new(verified);
            ctx.network
                .broadcast_global(&RatifyVoteGossip::new(Arc::new(Verifiable::from(
                    (*vote).clone(),
                ))));
            ctx.notify_protocol(ProtocolEvent::VerifiedRatifyVoteReceived { vote });
        }
        Action::BroadcastBeaconCandidate { candidate } => {
            ctx.network
                .broadcast_global(&BeaconCandidateGossip::new(Arc::new(Verifiable::from(
                    Arc::unwrap_or_clone(candidate),
                ))));
        }
        Action::VerifyBeaconBlock {
            block,
            committee,
            active_pool,
            equivocation_signers,
        } => {
            let result = Arc::unwrap_or_clone(block)
                .upgrade(&CertifiedBeaconBlockVerifyContext {
                    verifier: ctx.verifier,
                    network,
                    committee: &committee,
                    active_pool: &active_pool,
                    equivocation_signers: &equivocation_signers,
                })
                .map(Arc::new)
                .map_err(|(_, e)| e);
            ctx.notify_protocol(ProtocolEvent::BeaconBlockVerified { result });
        }
        Action::VerifyRatifyVote { vote, signers } => {
            let anchor = vote.anchor_hash();
            let epoch = vote.epoch();
            let round = vote.round();
            let phase = vote.phase();
            let signer = vote.signer();
            let result = (*vote)
                .upgrade(&RatifyVerifyContext {
                    verifier: ctx.verifier,
                    network,
                    active_pool: &signers,
                })
                .map_err(|(_, e)| e);
            ctx.notify_protocol(ProtocolEvent::RatifyVoteVerified {
                anchor,
                epoch,
                round,
                phase,
                signer,
                result,
            });
        }
        Action::VerifyBeaconCandidate {
            candidate,
            committee,
            equivocation_signers,
        } => {
            let result = Arc::unwrap_or_clone(candidate)
                .upgrade(&CandidateVerifyContext {
                    verifier: ctx.verifier,
                    network,
                    committee: &committee,
                    equivocation_signers: &equivocation_signers,
                })
                .map(Arc::new)
                .map_err(|(_, e)| e);
            ctx.notify_protocol(ProtocolEvent::BeaconCandidateVerified { result });
        }
        Action::VerifyPcVote1 {
            epoch,
            view,
            vote,
            committee,
        } => {
            let instance = PcScope { epoch, view };
            let signer = vote.validator();
            let result = vote.upgrade(&PcVoteVerifyContext {
                verifier: ctx.verifier,
                network,
                instance,
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
            let instance = PcScope { epoch, view };
            let signer = vote.validator();
            let result = (*vote).upgrade(&PcVoteVerifyContext {
                verifier: ctx.verifier,
                network,
                instance,
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
            let instance = PcScope { epoch, view };
            let signer = vote.validator();
            let result = (*vote).upgrade(&PcVoteVerifyContext {
                verifier: ctx.verifier,
                network,
                instance,
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
            let view = proposal.view;
            let result = (*proposal).upgrade(&SpcVerifyContext {
                verifier: ctx.verifier,
                network,
                epoch,
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
            let view = msg.view;
            let result = (*msg).upgrade(&SpcVerifyContext {
                verifier: ctx.verifier,
                network,
                epoch,
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
            let from = msg.signer;
            let view = msg.view;
            let result = (*msg).upgrade(&SpcVerifyContext {
                verifier: ctx.verifier,
                network,
                epoch,
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
