//! Delegated-action handlers for the beacon loop.
//!
//! [`handle_action`] runs a participant's [`ParticipantAction`] off the
//! driving thread on the Consensus dispatch pool; results return to the
//! participant via `ctx.notify(ProtocolEvent::*)`. [`verify_beacon_block`]
//! runs the fold's block checks. Mirrors
//! `hyperscale_shard::action_handlers::handle_action`. The context is the
//! storage-free [`BeaconActionContext`].

use std::sync::Arc;

use hyperscale_core::{
    BeaconActionContext, BeaconBlockCheck, GateEntry, ParticipantAction, ProtocolEvent,
};
use hyperscale_network::{Network, Verdict, VerdictKey};
use hyperscale_types::network::gossip::beacon::{
    BeaconBlockGossip, BeaconCandidateGossip, RatifyProof, RatifyVoteGossip,
};
use hyperscale_types::network::notification::{
    BeaconProposalNotification, PcVote1Notification, PcVote2Notification, PcVote3Notification,
    SpcEmptyViewMsgNotification, SpcNewCommitNotification, SpcNewViewNotification,
};
use hyperscale_types::{
    BeaconProposalDraft, BeaconVote, CandidateVerifyContext, CertifiedBeaconBlockVerifyContext,
    NetworkDefinition, PcScope, PcVote1, PcVote2, PcVote3, PcVoteVerifyContext, RatifyPhase,
    RatifyPolka, RatifyVerifyContext, RatifyVote, RatifyVoteVerifyError, SpcEmptyViewMsg,
    SpcRelayKind, SpcRelayMessage, SpcVerifyContext, Verifiable, Verified, Verifier, signed_bytes,
};

/// Admit `vote` through the durable beacon consensus register before
/// its signature exists. A slot the validator already signed, before a
/// restart or under an earlier participant, re-signs only the content it
/// holds;
/// anything else abstains, which costs at most this one signature,
/// never a double-sign.
fn admit_signature<N: Network>(ctx: &BeaconActionContext<'_, N>, vote: &BeaconVote) -> bool {
    if ctx.beacon_vote_registers.admit_beacon_vote(ctx.me, vote) {
        return true;
    }
    tracing::info!(
        epoch = vote.epoch().inner(),
        slot = ?vote.slot(),
        "beacon signature would contradict the durable register; abstaining"
    );
    false
}

/// Enter the participant's release gate for one signature, or `None`
/// once the participant is removed, and the action is dropped unsigned.
fn enter_gate<'c, N: Network>(
    ctx: &'c BeaconActionContext<'_, N>,
    action: &'static str,
) -> Option<GateEntry<'c>> {
    let entry = ctx.gate.enter();
    if entry.is_none() {
        tracing::trace!(action, "participant removed; dropping its signature");
    }
    entry
}

/// Run a participant's delegated work.
#[allow(clippy::too_many_lines)] // single dispatch over ParticipantAction variants
pub fn handle_action<N>(action: ParticipantAction, ctx: &BeaconActionContext<'_, N>)
where
    N: Network,
{
    let me = ctx.me;
    let network = ctx.topology_snapshot.network();
    match action {
        ParticipantAction::SignAndBroadcastPcVote1 {
            epoch,
            view,
            v_in,
            recipients,
        } => {
            let Some(_entry) = enter_gate(ctx, "SignAndBroadcastPcVote1") else {
                return;
            };
            if !admit_signature(ctx, &BeaconVote::pc_vote1(epoch, view, &v_in)) {
                return;
            }
            let instance = PcScope { epoch, view };
            let Ok(verified) =
                Verified::<PcVote1>::sign_local(ctx.signer.as_ref(), me, network, instance, v_in)
            else {
                tracing::error!(?view, "cannot sign PC vote1; abstaining");
                return;
            };
            ctx.network.notify(
                &recipients,
                &PcVote1Notification::new(
                    epoch,
                    view,
                    Arc::new(Verifiable::from(verified.clone())),
                ),
            );
            ctx.notify_protocol(ProtocolEvent::VerifiedPcVote1Received {
                epoch,
                view,
                vote: verified,
            });
        }
        ParticipantAction::SignAndBroadcastPcVote2 {
            epoch,
            view,
            qc1,
            recipients,
        } => {
            let Some(_entry) = enter_gate(ctx, "SignAndBroadcastPcVote2") else {
                return;
            };
            if !admit_signature(ctx, &BeaconVote::pc_vote2(epoch, view, &qc1)) {
                return;
            }
            let instance = PcScope { epoch, view };
            let Ok(verified) =
                Verified::<PcVote2>::sign_local(ctx.signer.as_ref(), me, network, instance, *qc1)
            else {
                tracing::error!(?view, "cannot sign PC vote2; abstaining");
                return;
            };
            ctx.network.notify(
                &recipients,
                &PcVote2Notification::new(
                    epoch,
                    view,
                    Arc::new(Verifiable::from(verified.clone())),
                ),
            );
            ctx.notify_protocol(ProtocolEvent::VerifiedPcVote2Received {
                epoch,
                view,
                vote: Box::new(verified),
            });
        }
        ParticipantAction::SignAndBroadcastPcVote3 {
            epoch,
            view,
            qc2,
            recipients,
        } => {
            let Some(_entry) = enter_gate(ctx, "SignAndBroadcastPcVote3") else {
                return;
            };
            if !admit_signature(ctx, &BeaconVote::pc_vote3(epoch, view, &qc2)) {
                return;
            }
            let instance = PcScope { epoch, view };
            let Ok(verified) =
                Verified::<PcVote3>::sign_local(ctx.signer.as_ref(), me, network, instance, *qc2)
            else {
                tracing::error!(?view, "cannot sign PC vote3; abstaining");
                return;
            };
            ctx.network.notify(
                &recipients,
                &PcVote3Notification::new(
                    epoch,
                    view,
                    Arc::new(Verifiable::from(verified.clone())),
                ),
            );
            ctx.notify_protocol(ProtocolEvent::VerifiedPcVote3Received {
                epoch,
                view,
                vote: Box::new(verified),
            });
        }
        ParticipantAction::SignAndBroadcastEmptyView {
            epoch,
            view,
            reported,
            recipients,
        } => {
            let Some(_entry) = enter_gate(ctx, "SignAndBroadcastEmptyView") else {
                return;
            };
            if !admit_signature(ctx, &BeaconVote::empty_view(epoch, view, &reported)) {
                return;
            }
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
                epoch,
                msg: Box::new(verified),
            });
        }
        ParticipantAction::BroadcastSpcNewView {
            epoch,
            proposal,
            recipients,
        } => {
            let Some(_entry) = enter_gate(ctx, "BroadcastSpcNewView") else {
                return;
            };
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
        ParticipantAction::BroadcastSpcNewCommit {
            epoch,
            msg,
            recipients,
        } => {
            let Some(_entry) = enter_gate(ctx, "BroadcastSpcNewCommit") else {
                return;
            };
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
        ParticipantAction::BuildAndBroadcastBeaconProposal {
            epoch,
            boundary_qcs,
            equivocations,
            fork_proofs,
            vote_equivocations,
            recipients,
        } => {
            let Some(_entry) = enter_gate(ctx, "BuildAndBroadcastBeaconProposal") else {
                return;
            };
            // The epoch's one proposal slot must be durable before the
            // body signature exists: a rebuilt participant whose evidence
            // buffers drained differently would otherwise sign a second
            // body for the epoch.
            let Ok(draft) = BeaconProposalDraft::new(
                ctx.signer.as_ref(),
                network,
                epoch,
                boundary_qcs,
                equivocations,
                fork_proofs,
                vote_equivocations,
            ) else {
                tracing::error!(?epoch, "cannot sign beacon proposal reveal; skipping");
                return;
            };
            if !admit_signature(ctx, &BeaconVote::proposal(epoch, draft.body_digest())) {
                return;
            }
            let Ok(verified) = draft.sign() else {
                tracing::error!(?epoch, "cannot sign beacon proposal; skipping");
                return;
            };
            (ctx.cache_beacon_proposal)(me, epoch, verified.clone());
            ctx.network.notify(
                &recipients,
                &BeaconProposalNotification::new(me, epoch, verified.clone()),
            );
            ctx.notify_protocol(ProtocolEvent::BeaconProposalReceived {
                from: me,
                epoch,
                proposal: verified,
            });
        }
        ParticipantAction::BroadcastBeaconBlock { block } => {
            ctx.network.broadcast_global(&BeaconBlockGossip::new(block));
        }
        ParticipantAction::SignAndBroadcastRatifyVote {
            anchor,
            epoch,
            round,
            phase,
            block_hash,
            proof,
        } => {
            // A proof holds at most a quorum of the pool, and a pool past
            // the cap indexes no signer bitfield, so no cert could form
            // there for a proof to help. A precommit carries the polka it
            // locks on: a member that lost one of its prevotes holds the
            // precommit without the quorum that licenses its own, and at an
            // exact quorum that one loss starves the certificate until the
            // next round re-sends the prevotes.
            let polka = match phase {
                RatifyPhase::Prevote => RatifyPolka::empty(),
                RatifyPhase::Precommit => {
                    RatifyPolka::new(proof.iter().cloned().map(Verified::into_inner).collect())
                        .unwrap_or_else(|_| {
                            tracing::error!(
                                ?epoch,
                                ?round,
                                "ratify polka exceeds its cap; storing none"
                            );
                            RatifyPolka::empty()
                        })
                }
            };
            let Some(_entry) = enter_gate(ctx, "SignAndBroadcastRatifyVote") else {
                return;
            };
            // The (round, phase) slot this vote consumes — and a
            // precommit's polka — must be durable before the signature
            // exists: a crash between them costs at most an abstention,
            // never a double-vote, a lost lock, or a lock without proof.
            if !ctx
                .ratify_registers
                .admit_ratify_vote(me, epoch, round, phase, block_hash, polka)
            {
                tracing::info!(
                    ?epoch,
                    ?round,
                    ?phase,
                    "ratify vote would contradict the durable register; abstaining"
                );
                return;
            }
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
            // A message that carries this vote as proof stands on it, and
            // this host never checks a vote it signed.
            ctx.network
                .settle(VerdictKey::of::<RatifyVote>(&vote), Verdict::Accept);
            let proof = RatifyProof::new(
                proof
                    .into_iter()
                    .map(|v| Arc::new(Verifiable::from(v)))
                    .collect(),
            )
            .unwrap_or_else(|_| {
                tracing::error!(?epoch, ?round, "ratify proof exceeds its cap; sending none");
                RatifyProof::empty()
            });
            ctx.network.broadcast_global(&RatifyVoteGossip::with_proof(
                Arc::new(Verifiable::from((*vote).clone())),
                proof,
            ));
            ctx.notify_protocol(ProtocolEvent::VerifiedRatifyVoteReceived { vote });
        }
        ParticipantAction::BroadcastBeaconCandidate { candidate } => {
            (ctx.cache_beacon_candidate)(candidate.clone());
            ctx.network
                .broadcast_global(&BeaconCandidateGossip::new(candidate));
        }
        ParticipantAction::VerifyRatifyVote { vote, signers } => {
            let anchor = vote.anchor_hash();
            let epoch = vote.epoch();
            let round = vote.round();
            let phase = vote.phase();
            let signer = vote.signer();
            let key = VerdictKey::of(vote.as_unverified());
            let result = (*vote)
                .upgrade(&RatifyVerifyContext {
                    verifier: ctx.verifier,
                    network,
                    active_pool: &signers,
                })
                .map_err(|(_, e)| e);
            // A signer outside this host's view of the pool may be one its
            // view has not caught up with; a bad signature is the vote's.
            ctx.network.settle(
                key,
                match result {
                    Ok(_) => Verdict::Accept,
                    Err(RatifyVoteVerifyError::BadSignature) => Verdict::Reject,
                    Err(RatifyVoteVerifyError::SignerNotInPool) => Verdict::Ignore,
                },
            );
            ctx.notify_protocol(ProtocolEvent::RatifyVoteVerified {
                anchor,
                epoch,
                round,
                phase,
                signer,
                result,
            });
        }
        ParticipantAction::VerifyBeaconCandidate {
            candidate,
            committee,
            equivocation_signers,
        } => {
            let key = VerdictKey::of(candidate.as_unverified());
            let block_hash = candidate.block_hash();
            let result = candidate
                .upgrade(&CandidateVerifyContext {
                    verifier: ctx.verifier,
                    network,
                    committee: &committee,
                    equivocation_signers: &equivocation_signers,
                })
                .map_err(|(_, e)| e);
            if let Ok(verified) = &result {
                (ctx.cache_beacon_candidate)(verified.clone());
            }
            ctx.network.settle(key, checked(result.is_ok()));
            ctx.notify_protocol(ProtocolEvent::BeaconCandidateVerified { block_hash, result });
        }
        ParticipantAction::VerifyPcVote1 {
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
        ParticipantAction::VerifyPcVote2 {
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
        ParticipantAction::VerifyPcVote3 {
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
        ParticipantAction::VerifySpcNewView {
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
        ParticipantAction::VerifySpcNewCommit {
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
        ParticipantAction::VerifySpcEmptyView {
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
    }
}

/// Run the fold's [`hyperscale_core::FoldAction::VerifyBeaconBlock`].
///
/// Checks the block's certificate, settles the gossip verdict deferred on
/// it, and hands the outcome to `notify`. The fold signs nothing, so the
/// check needs no participant's context.
pub fn verify_beacon_block<N: Network>(
    check: BeaconBlockCheck,
    verifier: &dyn Verifier,
    network: &NetworkDefinition,
    transport: &N,
    notify: &dyn Fn(ProtocolEvent),
) {
    let BeaconBlockCheck {
        block,
        committee,
        active_pool,
        equivocation_signers,
    } = check;
    // A gossip handler deferred its verdict on the block to this check;
    // the fold dispatches it only for a block it can place, so a failure
    // is the block's own.
    let key = VerdictKey::of(block.as_unverified());
    let result = block
        .upgrade(&CertifiedBeaconBlockVerifyContext {
            verifier,
            network,
            committee: &committee,
            active_pool: &active_pool,
            equivocation_signers: &equivocation_signers,
        })
        .map_err(|(_, e)| e);
    transport.settle(key, checked(result.is_ok()));
    notify(ProtocolEvent::BeaconBlockVerified { result });
}

/// The gossip verdict of a check that either holds or fails on the item
/// itself.
const fn checked(valid: bool) -> Verdict {
    if valid {
        Verdict::Accept
    } else {
        Verdict::Reject
    }
}
