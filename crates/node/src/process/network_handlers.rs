//! Network handler registration (gossip, notifications, requests).

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_execution::attesting_committee;
use hyperscale_hbor::{Bytes, Capped};
use hyperscale_metrics::{record_crossing_push_dropped, record_fetch_response_sent};
use hyperscale_network::{Network, Provenance, Verdict, VerdictKey};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::gossip::{
    CertifiedBlockHeaderGossip, ShardForkProofGossip, ShardVoteEquivocationGossip,
    TransactionGossip,
};
use hyperscale_types::network::notification::beacon::{
    BeaconProposalNotification, PcVote1Notification, PcVote2Notification, PcVote3Notification,
    SpcEmptyViewMsgNotification, SpcNewCommitNotification, SpcNewViewNotification,
};
use hyperscale_types::network::notification::{
    BlockHeaderNotification, BlockVoteNotification, CrossingReadingsNotification,
    ExecutionCertificatesNotification, ExecutionVoteNotification, ProvisionsNotification,
    QcAnnouncementNotification, ReadySignalNotification, TimeoutNotification,
};
use hyperscale_types::network::request::beacon::{
    GetBeaconBlockRequest, GetBeaconCandidateRequest, GetBeaconProposalRequest,
    GetShardWitnessesRequest,
};
use hyperscale_types::network::request::{GetFinalizationsRequest, GetLocalProvisionsRequest};
use hyperscale_types::network::response::GetProvisionResponse;
use hyperscale_types::{
    BeaconProposal, ExecutionCertificate, HeaderSource, ShardId, Signed, Verifiable, signed_bytes,
};
use tracing::warn;

use crate::beacon::gossip::register_beacon_gossip_handlers;
use crate::event::{HostEvent, Offer, ShardInbox, ShardScopedInput};
use crate::host::NodeHost;
use crate::process::ProcessIo;
use crate::process::single_flight::{Flight, SingleFlight};
use crate::serve::Served;
use crate::shard::cross_shard::crossing_push;
use crate::shard::verify::{
    resolve_sender_key, verify_sig_with_metrics, verify_signed_by_committee,
    verify_signed_by_proposer,
};
use crate::shard::{ShardIo, offer_network_event, offer_network_input};

impl<S, N, D> NodeHost<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Register gossip handlers for broadcast message types (transactions
    /// and committed block headers).
    ///
    /// Both handler closures see a single `(message, target_shard)` pair —
    /// the network framework computes the per-shard fan-out from each
    /// type's [`GossipMessage::SCOPE`] and [`GossipMessage::source_shard`].
    /// Closures here just translate into `ShardScopedInput`.
    #[allow(clippy::too_many_lines)] // single registration table; one closure per gossip type
    pub(crate) fn register_gossip_handlers(&self) {
        // ── transaction.gossip → ShardScopedInput::TransactionGossipReceived ─

        let senders = self.process.shard_event_senders.clone();
        let canonical_txs = Arc::clone(&self.process.canonical_txs);
        self.process
            .network
            .register_gossip_handler::<TransactionGossip>(
                move |gossip: TransactionGossip,
                      shard: ShardId,
                      provenance: Provenance|
                      -> Verdict {
                    let senders = senders.load();
                    let Some(tx) = senders.get(&shard) else {
                        warn!(
                            shard = shard.inner(),
                            "Dropping tx gossip: shard not hosted"
                        );
                        return Verdict::Ignore;
                    };
                    for transaction in gossip.transactions {
                        // A cross-shard tx arrives once per hosted shard
                        // topic, each a fresh decode; canonicalizing here
                        // lets the shards share one validation verdict.
                        let transaction = canonical_txs.canonicalize(&transaction);
                        if let Some(refusal) = offer_network_input(
                            tx,
                            shard,
                            ShardScopedInput::TransactionGossipReceived { tx: transaction },
                            provenance,
                        )
                        .refusal()
                        {
                            return refusal;
                        }
                    }
                    Verdict::Accept
                },
            );

        // ── block.committed → ShardScopedInput::CommittedBlockGossipReceived ─
        //
        // The framework already filters out the header's source shard,
        // so `target_shard` here is a hosted shard that needs this
        // header for cross-shard provisioning bookkeeping.

        let senders = self.process.shard_event_senders.clone();
        let topology_snapshot = self.process.topology_snapshot.clone();
        // Weak: the network holds this handler and the process holds the
        // network, so a strong handle would keep the process, and its
        // stores, alive past the host.
        let process = Arc::downgrade(&self.process);
        self.process
            .network
            .register_gossip_handler::<CertifiedBlockHeaderGossip>(
                move |gossip: CertifiedBlockHeaderGossip,
                      target_shard: ShardId,
                      provenance: Provenance|
                      -> Verdict {
                    let senders = senders.load();
                    let Some(tx) = senders.get(&target_shard) else {
                        warn!(
                            target_shard = target_shard.inner(),
                            "Dropping certified header gossip: shard not hosted"
                        );
                        return Verdict::Ignore;
                    };
                    let sender = gossip.sender;
                    // The host's own broadcast: no sender to authenticate,
                    // and a quorum the host certified itself rides its
                    // mark past a second check.
                    if provenance == Provenance::Local {
                        let event = match gossip.certified_header.into_verified() {
                            Ok(certified_header) => ProtocolEvent::VerifiedRemoteHeaderReceived {
                                certified_header,
                                sender,
                            },
                            Err(certified_header) => {
                                ProtocolEvent::UnverifiedRemoteHeaderReceived {
                                    certified_header,
                                    source: HeaderSource::Gossip(sender),
                                }
                            }
                        };
                        return offer_network_event(tx, target_shard, event, provenance).verdict();
                    }
                    let header = gossip.certified_header.header();
                    let header_shard = header.shard_id();
                    // The committee that signed the header, resolved at
                    // the header's own hash-pinned anchor and clamped to
                    // the shard's terminal window — not the head's.
                    // A split parent leaves the head's committees at its
                    // cut and coasts to its terminal's commit proof,
                    // broadcasting exactly the headers the crossing tracker
                    // reads its terminal QC off; against the head those
                    // resolve to an empty committee and every receiver
                    // rejects them.
                    let Some(process) = process.upgrade() else {
                        return Verdict::Ignore;
                    };
                    let schedule = process.topology_schedule();
                    let Some((signing, _)) = schedule
                        .at_for_shard(header_shard, header.parent_qc().weighted_timestamp())
                    else {
                        warn!(
                            sender = sender.inner(),
                            shard = header_shard.inner(),
                            "certified header gossip at a window the schedule does not hold"
                        );
                        return Verdict::Ignore;
                    };
                    // The schedule holds the window, so it says who signed
                    // there: a sender outside that committee is false on
                    // its face. A member whose key the head topology no
                    // longer carries is this host's own gap.
                    if !signing.committee_for_shard(header_shard).contains(&sender) {
                        warn!(
                            sender = sender.inner(),
                            shard = header_shard.inner(),
                            "certified header sender not in the committee that signed it"
                        );
                        return Verdict::Reject;
                    }
                    let topo = topology_snapshot.load();
                    let Some(public_key) = resolve_sender_key(
                        signing,
                        &topo,
                        sender,
                        header_shard,
                        "certified header",
                    ) else {
                        return Verdict::Ignore;
                    };

                    // The header travels on only once both its checks hold:
                    // the shard loop's of the sender signature, and the
                    // remote header coordinator's of the quorum certificate,
                    // which runs once the signature holds.
                    let checks = [
                        VerdictKey::from_digest(gossip.copy_digest()),
                        VerdictKey::from_digest(
                            gossip.certified_header.as_unverified().copy_digest(),
                        ),
                    ];
                    if let Some(refusal) = offer_network_input(
                        tx,
                        target_shard,
                        ShardScopedInput::CommittedBlockGossipReceived {
                            certified_header: gossip.certified_header,
                            sender,
                            public_key,
                            sender_signature: gossip.sender_signature,
                        },
                        provenance,
                    )
                    .refusal()
                    {
                        return refusal;
                    }
                    Verdict::defer_all(checks)
                },
            );

        // ── shard.fork_proof → ShardScopedInput::ShardForkProofGossipReceived ─
        //
        // A self-authenticating fork proof: no sender trust to resolve. The
        // framework filters out the forked shard, so `target_shard` is a
        // hosted consumer that fences against it.

        let senders = self.process.shard_event_senders.clone();
        self.process
            .network
            .register_gossip_handler::<ShardForkProofGossip>(
                move |gossip: ShardForkProofGossip,
                      target_shard: ShardId,
                      provenance: Provenance|
                      -> Verdict {
                    let senders = senders.load();
                    let Some(tx) = senders.get(&target_shard) else {
                        warn!(
                            target_shard = target_shard.inner(),
                            "Dropping fork proof gossip: shard not hosted"
                        );
                        return Verdict::Ignore;
                    };
                    offer_network_input(
                        tx,
                        target_shard,
                        ShardScopedInput::ShardForkProofGossipReceived {
                            proof: gossip.proof,
                        },
                        provenance,
                    )
                    .verdict()
                },
            );

        // Shard double-vote evidence: same self-authenticating global
        // gossip shape as fork proofs. A hosting host carries it to its
        // beacon loop, which verifies it off-thread for the next beacon
        // proposal.
        let senders = self.process.shard_event_senders.clone();
        let beacon_tx = self.process.beacon_event_sender.clone();
        self.process
            .network
            .register_gossip_handler::<ShardVoteEquivocationGossip>(
                move |gossip: ShardVoteEquivocationGossip,
                      target_shard: ShardId,
                      _provenance: Provenance|
                      -> Verdict {
                    if !senders.load().contains_key(&target_shard) {
                        warn!(
                            target_shard = target_shard.inner(),
                            "Dropping double-vote gossip: shard not hosted"
                        );
                        return Verdict::Ignore;
                    }
                    let _ = beacon_tx.send(HostEvent::beacon(
                        ProtocolEvent::UnverifiedShardVoteEquivocationReceived {
                            evidence: Box::new(Arc::unwrap_or_clone(gossip.evidence)),
                        },
                    ));
                    Verdict::Accept
                },
            );

        // Beacon gossip (beacon.block, beacon.candidate and
        // beacon.ratify_vote, per shard and host-level) lives in
        // `crate::beacon::gossip` — the closures capture only the senders
        // and the beacon loop's channel.
        register_beacon_gossip_handlers(
            &*self.process.network,
            &self.process.shard_event_senders,
            &self.process.beacon_event_sender,
        );
    }

    /// Register notification handlers for protocol messages sent via unicast
    /// to known committee members.
    #[allow(clippy::too_many_lines)] // single registration table; one closure per notification type
    pub(crate) fn register_notification_handlers(&self) {
        // ── block.vote → ProtocolEvent::{Verified,Unverified}BlockVoteReceived ──
        //
        // `BlockVote.shard_id()` is the shard whose consensus the
        // vote is for; on a host carrying several shards that selects
        // the loop the event goes to. Drop early if the vote targets a
        // shard we don't host.
        //
        // Wire decode lands the wrapper as `Verifiable::Unverified`;
        // local-dispatched sends from a colocated voter arrive already
        // verified and skip the state machine's verify round-trip.

        let senders = self.process.shard_event_senders.clone();
        self.process
            .network
            .register_notification_handler::<BlockVoteNotification>(
                move |gossip: BlockVoteNotification, provenance: Provenance| -> Verdict {
                    let shard = gossip.vote.shard_id();
                    let senders = senders.load();
                    let Some(tx) = senders.get(&shard) else {
                        warn!(
                            target_shard = shard.inner(),
                            "Dropping block vote: shard not hosted"
                        );
                        return Verdict::Ignore;
                    };
                    let event = match gossip.vote.into_verified() {
                        Ok(vote) => ProtocolEvent::VerifiedBlockVoteReceived { vote },
                        Err(vote) => ProtocolEvent::UnverifiedBlockVoteReceived { vote },
                    };
                    offer_network_event(tx, shard, event, provenance).verdict()
                },
            );

        // ── shard.timeout → ProtocolEvent::{Verified,Unverified}TimeoutReceived ─
        let senders = self.process.shard_event_senders.clone();
        self.process
            .network
            .register_notification_handler::<TimeoutNotification>(
                move |gossip: TimeoutNotification, provenance: Provenance| -> Verdict {
                    let shard = gossip.timeout.shard_id();
                    let senders = senders.load();
                    let Some(tx) = senders.get(&shard) else {
                        warn!(
                            target_shard = shard.inner(),
                            "Dropping timeout: shard not hosted"
                        );
                        return Verdict::Ignore;
                    };
                    let event = match gossip.timeout.into_verified() {
                        Ok(timeout) => ProtocolEvent::VerifiedTimeoutReceived { timeout },
                        Err(timeout) => ProtocolEvent::UnverifiedTimeoutReceived { timeout },
                    };
                    offer_network_event(tx, shard, event, provenance).verdict()
                },
            );

        // ── shard.qc → ProtocolEvent::QcAnnouncementReceived ─
        //
        // The coordinator screens the announcer and round before it spends a
        // signature check or a QC verification on one.
        let senders = self.process.shard_event_senders.clone();
        self.process
            .network
            .register_notification_handler::<QcAnnouncementNotification>(
                move |announcement: QcAnnouncementNotification,
                      provenance: Provenance|
                      -> Verdict {
                    let shard = announcement.qc.shard_id();
                    let senders = senders.load();
                    let Some(tx) = senders.get(&shard) else {
                        return Verdict::Ignore;
                    };
                    offer_network_event(
                        tx,
                        shard,
                        ProtocolEvent::QcAnnouncementReceived { announcement },
                        provenance,
                    )
                    .verdict()
                },
            );

        // ── block.header → verify proposer sig, then ShardScopedInput::ProposalReceived ─

        let senders = self.process.shard_event_senders.clone();
        let topology_snapshot = self.process.topology_snapshot.clone();
        let verifier = Arc::clone(&self.process.verifier);
        self.process
            .network
            .register_notification_handler::<BlockHeaderNotification>(
                move |gossip: BlockHeaderNotification, provenance: Provenance| -> Verdict {
                    let shard = gossip.header.shard_id();
                    let senders = senders.load();
                    let Some(tx) = senders.get(&shard) else {
                        warn!(
                            target_shard = shard.inner(),
                            "Dropping block header: shard not hosted"
                        );
                        return Verdict::Ignore;
                    };
                    let verdict = provenance.check(|| {
                        verify_signed_by_proposer(
                            verifier.as_ref(),
                            &topology_snapshot.load(),
                            &gossip,
                            "block_header",
                            "block header",
                        )
                    });
                    if verdict != Verdict::Accept {
                        return verdict;
                    }
                    offer_network_input(
                        tx,
                        shard,
                        ShardScopedInput::ProposalReceived {
                            proposal: Box::new(gossip),
                        },
                        provenance,
                    )
                    .verdict()
                },
            );

        // ── provisions.broadcast → ProtocolEvent::{Verified,Unverified}ProvisionsReceived ─
        //
        // Wire decode lands the wrapper as `Verifiable::Unverified`;
        // local-dispatched sends from a colocated source-shard proposer
        // arrive already verified and skip the state machine's
        // `Action::VerifyProvisions` dispatch. The envelope signature is
        // checked only on a peer's copy.

        let senders = self.process.shard_event_senders.clone();
        let topology_snapshot = self.process.topology_snapshot.clone();
        let verifier = Arc::clone(&self.process.verifier);
        self.process
            .network
            .register_notification_handler::<ProvisionsNotification>(
                move |notification: ProvisionsNotification, provenance: Provenance| -> Verdict {
                    let target_shard = notification.provisions.target_shard();
                    // Drop provisions not destined for any hosted shard before
                    // paying the signature verification cost.
                    let senders = senders.load();
                    let Some(tx) = senders.get(&target_shard) else {
                        warn!(
                            source_shard = notification.provisions.source_shard().inner(),
                            target_shard = target_shard.inner(),
                            "Dropping provisions notification: target_shard not hosted"
                        );
                        return Verdict::Ignore;
                    };

                    let verdict = provenance.check(|| {
                        let topo = topology_snapshot.load();
                        verify_signed_by_committee(
                            verifier.as_ref(),
                            &topo,
                            &topo,
                            notification.provisions.source_shard(),
                            &notification,
                            "state_provisions",
                            "state provision",
                        )
                    });
                    if verdict != Verdict::Accept {
                        return verdict;
                    }
                    let event = match notification.provisions.into_verified() {
                        Ok(provisions) => ProtocolEvent::VerifiedProvisionsReceived { provisions },
                        Err(provisions) => {
                            ProtocolEvent::UnverifiedProvisionsReceived { provisions }
                        }
                    };
                    offer_network_event(tx, target_shard, event, provenance).verdict()
                },
            );

        // ── crossing.readings → ProtocolEvent::CrossingReadingsReceived ─
        //
        // A producer's pushed record readings. Nothing is held before
        // every check passes: routed and cheap first, then the sender
        // against the committee that proposed the anchor's block —
        // resolved at the anchor's own clock, since the head names an
        // empty committee for a split parent's coast blocks and drops a
        // member rotated out since — then each claim's own proof, on
        // this thread as the signature was. The host's own push is taken
        // unchecked.

        let senders = self.process.shard_event_senders.clone();
        let topology_snapshot = self.process.topology_snapshot.clone();
        // Weak: the network holds this handler and the process holds the
        // network, so a strong handle would keep the process, and its
        // stores, alive past the host.
        let process = Arc::downgrade(&self.process);
        let verifier = Arc::clone(&self.process.verifier);
        self.process
            .network
            .register_notification_handler::<CrossingReadingsNotification>(
                move |notification: CrossingReadingsNotification,
                      provenance: Provenance|
                      -> Verdict {
                    let target_shard = notification.target_shard;
                    let senders = senders.load();
                    let Some(tx) = senders.get(&target_shard) else {
                        record_crossing_push_dropped("unhosted");
                        return Verdict::Ignore;
                    };
                    let verdict = provenance.check(|| {
                        let anchor = match crossing_push::shaped(&notification) {
                            Ok(anchor) => anchor,
                            Err(reason) => {
                                record_crossing_push_dropped(reason);
                                return Verdict::Reject;
                            }
                        };
                        let Some(process) = process.upgrade() else {
                            return Verdict::Ignore;
                        };
                        let schedule = process.topology_schedule();
                        let Some((signing, _)) = schedule.at_for_shard(anchor.shard, anchor.ts)
                        else {
                            record_crossing_push_dropped("unscheduled_anchor");
                            return Verdict::Ignore;
                        };
                        let topo = topology_snapshot.load();
                        let Some(public_key) = resolve_sender_key(
                            signing,
                            &topo,
                            notification.signer(),
                            anchor.shard,
                            "crossing readings",
                        ) else {
                            record_crossing_push_dropped("sender");
                            return Verdict::Ignore;
                        };
                        let msg = notification.signing_message(topo.network());
                        if !verify_sig_with_metrics(
                            verifier.as_ref(),
                            &msg,
                            &public_key,
                            notification.signature(),
                            "crossing_readings",
                        ) {
                            record_crossing_push_dropped("signature");
                            return Verdict::Reject;
                        }
                        // The claims ride under the producer's signature, so
                        // a claim that proves nothing is the producer's.
                        if let Err(reason) = crossing_push::proven(&notification.claims) {
                            record_crossing_push_dropped(reason);
                            return Verdict::Reject;
                        }
                        Verdict::Accept
                    });
                    if verdict != Verdict::Accept {
                        return verdict;
                    }
                    let offered = offer_network_event(
                        tx,
                        target_shard,
                        ProtocolEvent::CrossingReadingsReceived {
                            claims: notification.claims.into_inner(),
                        },
                        provenance,
                    );
                    match offered {
                        Offer::Taken => {}
                        Offer::Full => record_crossing_push_dropped("lane_full"),
                        Offer::OverShare => record_crossing_push_dropped("over_share"),
                    }
                    offered.verdict()
                },
            );

        // ── execution.vote → ProtocolEvent::ExecutionVoteReceived ─────

        let senders = self.process.shard_event_senders.clone();
        self.process
            .network
            .register_notification_handler::<ExecutionVoteNotification>(
                move |gossip: ExecutionVoteNotification, provenance: Provenance| -> Verdict {
                    let shard = gossip.vote.tick_id().shard_id();
                    let senders = senders.load();
                    let Some(tx) = senders.get(&shard) else {
                        warn!(
                            target_shard = shard.inner(),
                            "Dropping execution vote: shard not hosted"
                        );
                        return Verdict::Ignore;
                    };
                    // Wire decode lands the wrapper as
                    // `Verifiable::Unverified`; local-dispatched sends
                    // from a colocated voter arrive already verified and
                    // skip the state machine's verify round-trip. The
                    // vote carries its own voter and signature, so there
                    // is no relay to authenticate: the coordinator holds
                    // it to the committee seated at its anchor and then
                    // to its own signature.
                    offer_network_event(
                        tx,
                        shard,
                        ProtocolEvent::ExecutionVoteReceived {
                            vote: gossip.into_vote(),
                        },
                        provenance,
                    )
                    .verdict()
                },
            );

        // ── execution.cert.batch → verify sender sig, then ProtocolEvent::ExecutionCertificatesReceived ─
        //
        // The cert's `shard_id` is the *source* shard (sender's
        // shard). With cross-shard hosting we may consume an EC for any
        // of our hosted shards as the destination, so the relevant
        // "target hosted shard" is determined later by the state machine.
        // For routing purposes we forward to every hosted shard so
        // each receiving coordinator can decide whether the cert is for it.

        let senders = self.process.shard_event_senders.clone();
        let topology_snapshot = self.process.topology_snapshot.clone();
        let verifier = Arc::clone(&self.process.verifier);
        // Weak: the network holds this handler and the process holds the
        // network, so a strong handle would keep the process, and its
        // stores, alive past the host.
        let process = Arc::downgrade(&self.process);
        self.process
            .network
            .register_notification_handler::<ExecutionCertificatesNotification>(
                move |batch: ExecutionCertificatesNotification,
                      provenance: Provenance|
                      -> Verdict {
                    let verdict = provenance.check(|| {
                        let sender = batch.sender;
                        // No honest leader sends an empty batch.
                        if batch.certificates.is_empty() {
                            return Verdict::Reject;
                        }

                        let source_shard = batch.certificates[0].shard_id();
                        if batch
                            .certificates
                            .iter()
                            .any(|c| c.shard_id() != source_shard)
                        {
                            warn!(
                                sender = sender.inner(),
                                "Execution certificate batch contains mixed shard_ids — dropping"
                            );
                            return Verdict::Reject;
                        }
                        // The sender is the tick leader that aggregated the
                        // certificates, so it sits in the committee attesting
                        // each one. At an epoch cut that committee holds members
                        // the head no longer seats: a departing leader still
                        // certifies the ticks its window anchored.
                        let Some(process) = process.upgrade() else {
                            return Verdict::Ignore;
                        };
                        let schedule = process.topology_schedule();
                        let Some(attesting) = batch
                            .certificates
                            .iter()
                            .map(|cert| {
                                attesting_committee(&schedule, source_shard, cert.vote_anchor_ts())
                            })
                            .collect::<Option<Vec<_>>>()
                        else {
                            warn!(
                                sender = sender.inner(),
                                shard = source_shard.inner(),
                                "Execution certificate batch at a window the schedule does not hold"
                            );
                            return Verdict::Ignore;
                        };
                        // The schedule holds every certificate's window, so it
                        // says who attests there: a sender outside one of those
                        // committees is false on its face.
                        if attesting.iter().any(|committee| {
                            !committee
                                .committee_for_shard(source_shard)
                                .contains(&sender)
                        }) {
                            warn!(
                                sender = sender.inner(),
                                shard = source_shard.inner(),
                                "Execution certificate batch sender does not attest every certificate"
                            );
                            return Verdict::Reject;
                        }
                        let topo = topology_snapshot.load();
                        verify_signed_by_committee(
                            verifier.as_ref(),
                            attesting[0],
                            &topo,
                            source_shard,
                            &batch,
                            "exec_cert_batch",
                            "execution certificate batch",
                        )
                    });
                    if verdict != Verdict::Accept {
                        return verdict;
                    }

                    let certificates: Vec<Verifiable<ExecutionCertificate>> = batch
                        .into_certificates()
                        .into_iter()
                        .map(Verifiable::from)
                        .collect();
                    // Fan out across every hosted shard — the destination
                    // shard for a cert isn't known here without inspecting
                    // expected-cert sets, so each hosted shard decides
                    // whether to admit (no-op if unexpected).
                    offer_to_each(
                        senders.load().iter(),
                        certificates,
                        |certificates| ProtocolEvent::ExecutionCertificatesReceived {
                            certificates,
                        },
                        provenance,
                    )
                },
            );

        // ── ready_signal → verify sender signature, then ProtocolEvent::ReadySignalReceived ─
        //
        // The signal names the shard whose state its sender synced, and
        // the committees that take it all sit on that shard's trie line:
        // the shard's own committee for a joining member, the splitting
        // parent's for an observer readying a child, and each merging
        // child's for a keeper readying the parent. Only hosted shards on
        // that line are offered it; each pool drops the signal if the
        // sender holds no seat it admits.

        let senders = self.process.shard_event_senders.clone();
        let topology_snapshot = self.process.topology_snapshot.clone();
        let verifier = Arc::clone(&self.process.verifier);
        self.process
            .network
            .register_notification_handler::<ReadySignalNotification>(
                move |notification: ReadySignalNotification, provenance: Provenance| -> Verdict {
                    let signal = notification.signal;
                    let line = signal.shard();
                    let senders = senders.load();
                    let mut targets = senders
                        .iter()
                        .filter(|(hosted, _)| {
                            hosted.is_ancestor_of(line) || line.is_ancestor_of(**hosted)
                        })
                        .peekable();
                    if targets.peek().is_none() {
                        return Verdict::Ignore;
                    }
                    let verdict = provenance.check(|| {
                        let topo = topology_snapshot.load();
                        let sender = signal.validator_id();
                        let Some(public_key) = topo.public_key(sender) else {
                            warn!(
                                sender = sender.inner(),
                                "Dropping ready signal: unknown sender"
                            );
                            return Verdict::Ignore;
                        };
                        let msg = signed_bytes(&signal, topo.network());
                        if !verify_sig_with_metrics(
                            verifier.as_ref(),
                            &msg,
                            &public_key,
                            &signal.sig(),
                            "ready_signal",
                        ) {
                            warn!(
                                sender = sender.inner(),
                                "Ready signal signature verify failed — dropping"
                            );
                            return Verdict::Reject;
                        }
                        Verdict::Accept
                    });
                    if verdict != Verdict::Accept {
                        return verdict;
                    }
                    offer_to_each(
                        targets,
                        signal,
                        |signal| ProtocolEvent::ReadySignalReceived { signal },
                        provenance,
                    )
                },
            );

        // ── beacon.proposal → BeaconProposalReceived ──
        //
        // Beacon-committee unicast, to the host's beacon loop, whose
        // participants each decide admission. The VRF reveal is checked
        // here, once, under the sender's key from the topology the
        // beacon loop publishes at each adoption (the network thread
        // cannot read the fold, and both name a committee member's key
        // alike); local-dispatched sends keep their `Verified` marker
        // and skip it. Only a proposal that holds reaches the loop, and
        // the process-level serve cache keeps a copy so
        // `GetBeaconProposalRequest` is answered without reading any
        // participant's pool. Only its author notifies a proposal, so a
        // peer's verdict waits on the participants' check of the
        // evidence it carries, which the loop settles.
        let proposal_cache = Arc::clone(&self.process.dispatch_handles.beacon_proposal_cache);
        let topology_snapshot = self.process.topology_snapshot.clone();
        let verifier = Arc::clone(&self.process.verifier);
        let beacon_tx = self.process.beacon_event_sender.clone();
        self.process
            .network
            .register_notification_handler::<BeaconProposalNotification>(
                move |gossip: BeaconProposalNotification, provenance: Provenance| -> Verdict {
                    let from = gossip.sender;
                    let epoch = gossip.epoch;
                    let Some(sender_pk) = topology_snapshot.load().public_key(from) else {
                        return Verdict::Ignore;
                    };
                    let Some(proposal) = proposal_cache.admit_wire(
                        verifier.as_ref(),
                        from,
                        epoch,
                        gossip.proposal,
                        sender_pk,
                    ) else {
                        return Verdict::Reject;
                    };
                    let key = VerdictKey::of::<BeaconProposal>(&proposal);
                    let event = ProtocolEvent::BeaconProposalReceived {
                        from,
                        epoch,
                        proposal,
                    };
                    let _ = beacon_tx.send(HostEvent::beacon(event));
                    match provenance {
                        Provenance::Local => Verdict::Accept,
                        Provenance::Peer(_) => Verdict::defer(key),
                    }
                },
            );

        // ── beacon.pc.vote1/2/3 → Unverified/VerifiedPcVote{N}Received ──
        //
        // PC votes carry the wrapping `epoch` and `view` because the inner
        // vote doesn't encode its scope; the receiver routes by both.
        macro_rules! register_pc_vote_handler {
            ($note_ty:ty, $unv:ident, $ver:ident, $vote_ty:ty $(, $box:tt)?) => {{
                let beacon_tx = self.process.beacon_event_sender.clone();
                self.process.network.register_notification_handler::<$note_ty>(
                    move |gossip: $note_ty, _provenance: Provenance| -> Verdict {
                        let epoch = gossip.epoch;
                        let view = gossip.view;
                        let event = match Arc::unwrap_or_clone(gossip.vote).into_verified() {
                            Ok(verified) => ProtocolEvent::$ver {
                                epoch,
                                view,
                                vote: register_pc_vote_handler!(@wrap $($box)? verified),
                            },
                            Err(unverified) => ProtocolEvent::$unv {
                                epoch,
                                view,
                                vote: register_pc_vote_handler!(@wrap $($box)? unverified.into()),
                            },
                        };
                        let _ = beacon_tx.send(HostEvent::beacon(event));
                        Verdict::Accept
                    },
                );
            }};
            (@wrap box $e:expr) => { Box::new($e) };
            (@wrap $e:expr) => { $e };
        }
        register_pc_vote_handler!(
            PcVote1Notification,
            UnverifiedPcVote1Received,
            VerifiedPcVote1Received,
            PcVote1
        );
        register_pc_vote_handler!(
            PcVote2Notification,
            UnverifiedPcVote2Received,
            VerifiedPcVote2Received,
            PcVote2,
            box
        );
        register_pc_vote_handler!(
            PcVote3Notification,
            UnverifiedPcVote3Received,
            VerifiedPcVote3Received,
            PcVote3,
            box
        );

        // ── beacon.spc.new_view → ProtocolEvent::SpcNewViewReceived ─
        //
        // The wrapper carries `sender + sender_signature` for relay
        // accountability — the embedded cert self-authenticates content,
        // the wrapper sig attributes "this validator relayed it" so the
        // coordinator can key per-`(epoch, view, sender)` pipeline slots.
        // A peer's sig is verified under the sender's pubkey before fanning
        // in; signature check fails → drop (`verify_signed_by_proposer`
        // already warns).
        let topology_snapshot = self.process.topology_snapshot.clone();
        let verifier = Arc::clone(&self.process.verifier);
        let beacon_tx = self.process.beacon_event_sender.clone();
        self.process
            .network
            .register_notification_handler::<SpcNewViewNotification>(
                move |gossip: SpcNewViewNotification, provenance: Provenance| -> Verdict {
                    let verdict = provenance.check(|| {
                        verify_signed_by_proposer(
                            verifier.as_ref(),
                            &topology_snapshot.load(),
                            &gossip,
                            "spc_new_view",
                            "SPC new view",
                        )
                    });
                    if verdict != Verdict::Accept {
                        return verdict;
                    }
                    let event = ProtocolEvent::SpcNewViewReceived {
                        epoch: gossip.epoch(),
                        from: gossip.sender,
                        proposal: gossip.proposal,
                    };
                    let _ = beacon_tx.send(HostEvent::beacon(event));
                    Verdict::Accept
                },
            );

        // ── beacon.spc.new_commit → ProtocolEvent::SpcNewCommitReceived ──
        let topology_snapshot = self.process.topology_snapshot.clone();
        let verifier = Arc::clone(&self.process.verifier);
        let beacon_tx = self.process.beacon_event_sender.clone();
        self.process
            .network
            .register_notification_handler::<SpcNewCommitNotification>(
                move |gossip: SpcNewCommitNotification, provenance: Provenance| -> Verdict {
                    let verdict = provenance.check(|| {
                        verify_signed_by_proposer(
                            verifier.as_ref(),
                            &topology_snapshot.load(),
                            &gossip,
                            "spc_new_commit",
                            "SPC new commit",
                        )
                    });
                    if verdict != Verdict::Accept {
                        return verdict;
                    }
                    let event = ProtocolEvent::SpcNewCommitReceived {
                        epoch: gossip.epoch(),
                        from: gossip.sender,
                        msg: gossip.msg,
                    };
                    let _ = beacon_tx.send(HostEvent::beacon(event));
                    Verdict::Accept
                },
            );

        // ── beacon.spc.empty_view → Unverified/VerifiedSpcEmptyViewReceived ──
        //
        // EmptyView is content-signed, so — like new_view/new_commit — we
        // authenticate the signer at the relay edge before the coordinator
        // keys a per-`(epoch, view, signer)` verification slot, blocking a
        // peer from squatting another validator's slot with a forged-signer
        // message. The host's own sends skip the check; the expensive
        // embedded-QC3 verify still runs async in the coordinator unless the
        // message carries its `Verified` marker.
        let topology_snapshot = self.process.topology_snapshot.clone();
        let verifier = Arc::clone(&self.process.verifier);
        let beacon_tx = self.process.beacon_event_sender.clone();
        self.process
            .network
            .register_notification_handler::<SpcEmptyViewMsgNotification>(
                move |gossip: SpcEmptyViewMsgNotification, provenance: Provenance| -> Verdict {
                    let verdict = provenance.check(|| {
                        verify_signed_by_proposer(
                            verifier.as_ref(),
                            &topology_snapshot.load(),
                            &gossip,
                            "spc_empty_view",
                            "SPC empty view",
                        )
                    });
                    if verdict != Verdict::Accept {
                        return verdict;
                    }
                    let epoch = gossip.epoch();
                    let event = match Arc::unwrap_or_clone(gossip.msg).into_verified() {
                        Ok(upgraded) => ProtocolEvent::VerifiedSpcEmptyViewReceived {
                            epoch,
                            msg: Box::new(upgraded),
                        },
                        Err(unverified) => ProtocolEvent::UnverifiedSpcEmptyViewReceived {
                            epoch,
                            msg: Arc::new(unverified.into()),
                        },
                    };
                    let _ = beacon_tx.send(HostEvent::beacon(event));
                    Verdict::Accept
                },
            );
    }
}

/// Offer the event `event` builds from `value` to each of `targets`'
/// network lanes, cloning `value` for all but the last, which takes it.
/// Each shard decides for itself whether the input is one it wants, so
/// the message counts as taken once any lane took it; it is refused only
/// when every lane offered it refused it, and charged to its peer when
/// any lane found the peer past its share.
fn offer_to_each<'a, T: Clone>(
    targets: impl IntoIterator<Item = (&'a ShardId, &'a ShardInbox)>,
    value: T,
    event: impl Fn(T) -> ProtocolEvent,
    provenance: Provenance,
) -> Verdict {
    let targets: Vec<_> = targets.into_iter().collect();
    let Some(((last_shard, last_inbox), rest)) = targets.split_last() else {
        return Verdict::Accept;
    };
    let mut offer = Offer::Full;
    for (shard, inbox) in rest {
        offer = offer.or(offer_network_event(
            inbox,
            **shard,
            event(value.clone()),
            provenance,
        ));
    }
    offer
        .or(offer_network_event(
            last_inbox,
            **last_shard,
            event(value),
            provenance,
        ))
        .verdict()
}

/// Register `serve` as `R`'s handler on `shard`, recording what each
/// answer carried as fetch responses sent under `R`'s own name.
fn register_served<R, N>(
    network: &N,
    shard: ShardId,
    serve: impl Fn(&R) -> R::Response + Send + Sync + 'static,
) where
    R: Served + Send + 'static,
    R::Response: Send + 'static,
    N: Network,
{
    network.register_request_handler::<R>(shard, move |req: R| {
        let response = serve(&req);
        record_fetch_response_sent(R::label(), req.served(&response));
        response
    });
}

/// Register one shard's per-type request handlers with the network.
///
/// Each handler is a closure that captures that shard's state and
/// delegates to the serving function in the corresponding protocol
/// module. Called once per shard — at init for startup shards and
/// again when a shard is added at runtime (after its `ShardLoop` is
/// seated, so the closures capture live `ShardIo` handles).
#[allow(clippy::too_many_lines)] // single registration table; one closure per request type
pub fn register_shard_request_handlers<S, N, D>(
    process: &Arc<ProcessIo<S, N, D>>,
    io: &ShardIo<S>,
    shard: ShardId,
) where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    use std::sync::Arc;

    use hyperscale_engine::Executor;
    use hyperscale_types::network::request::{
        GetBlockRequest, GetCellsRequest, GetInstanceRecordsRequest, GetPackageArtifactsRequest,
        GetProposalRequest, GetProvisionsRequest, GetRemoteHeadersRequest, GetSettledTxsRequest,
        GetStateProofRequest, GetStateRangeRequest, GetTransactionsRequest,
        GetWitnessHistoryRequest,
    };
    use hyperscale_types::network::response::{
        GetInstanceRecordsResponse, GetPackageArtifactsResponse,
    };

    use crate::beacon::block_serve::serve_beacon_block_request;
    use crate::beacon::witness_serve::serve_shard_witnesses_request;
    use crate::shard::consensus::serve_block_request;
    use crate::shard::cross_shard::{
        SettledTxsCache, serve_cells_request, serve_finalizations_request,
        serve_local_provisions_request, serve_provision_request, serve_remote_headers_request,
        serve_settled_txs_request, serve_state_proof_request,
    };
    use crate::shard::mempool::serve_transaction_request;
    use crate::{serve_state_range_request, serve_witness_history_request};

    // Cap how long a waiter blocks on a producer. Request handlers run on
    // tokio blocking-pool threads; without a bound, a stalled producer can
    // pin every waiter thread and eventually starve the pool.
    const PRODUCER_WAIT_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

    // Cap concurrent waiters on a single producer. Honest fan-out from
    // a remote committee can stack dozens of waiters on one (height,
    // shard) key; this cap covers that case while bounding the
    // blocking-pool footprint when a producer stalls. Waiters past
    // the cap return `None` immediately and let the caller retry —
    // by then the producer has typically published a result that the
    // cache fast path will serve.
    const MAX_WAITERS_PER_KEY: usize = 64;

    // Produced provisions kept per shard, by (height, target shard).
    const PROVISION_CACHE_CAPACITY: usize = 256;

    // Each handler closure captures this shard's `PendingChain` and
    // per-protocol caches. Every CHAIN read goes through
    // `PendingChain` so the shard-committed / JMT-persisted window is
    // reachable from one place; the snap-sync handler is the one
    // exception, reading raw storage because it serves pinned
    // boundary state, not the chain.
    // ── block.request → sync protocol ────────────────────────────

    let pending_chain = Arc::clone(&io.pending_chain);
    let provision_store = Arc::clone(&io.caches.provision_store);
    process
        .network
        .register_request_handler::<GetBlockRequest>(shard, move |req| {
            serve_block_request(&pending_chain, &provision_store, &req)
        });

    // ── transaction.request → fetch protocol ─────────────────────

    let pending_chain = Arc::clone(&io.pending_chain);
    let tx_store = Arc::clone(&io.caches.tx_store);
    register_served::<GetTransactionsRequest, _>(&*process.network, shard, move |req| {
        serve_transaction_request(&pending_chain, &tx_store, req)
    });

    // ── state_range.request → snap-sync boundary serving ─────────

    let storage = Arc::clone(&io.storage);
    register_served::<GetStateRangeRequest, _>(&*process.network, shard, move |req| {
        serve_state_range_request(&storage, req)
    });

    // ── package_artifact.request → published-code availability ───

    // Raw storage like snap-sync, and for the same reason: the package
    // index is a store-level CF over committed cells, not chain
    // content. A point lookup per id — this runs on the blocking pool,
    // where a scan would pin a thread per request.
    let storage = Arc::clone(&io.storage);
    register_served::<GetPackageArtifactsRequest, _>(
        &*process.network,
        shard,
        move |req: &GetPackageArtifactsRequest| {
            // An artifact the publish gate would have refused for
            // width is one no asker would admit either, so it is
            // absent from the answer rather than sent to be dropped.
            let artifacts: Vec<_> = req
                .packages
                .iter()
                .filter_map(|package| storage.package_artifact(*package))
                .filter_map(|artifact| Bytes::new(artifact).ok())
                .collect();
            GetPackageArtifactsResponse::new(
                Capped::new(artifacts).expect("no more answers than the request named"),
            )
        },
    );

    // ── instance_record.request → cross-shard component resolution ─

    // No index behind this, unlike the artifact serve beside it: a
    // component's configuration leaf sits at a key its own address
    // derives, so the request names where to look. Read at the store's
    // own committed height, which is what a record being immutable once
    // sealed makes safe — any height at or after the seal answers the
    // same bytes.
    let storage = Arc::clone(&io.storage);
    register_served::<GetInstanceRecordsRequest, _>(
        &*process.network,
        shard,
        move |req: &GetInstanceRecordsRequest| {
            let height = storage.jmt_height();
            let records: Vec<_> = req
                .instances
                .iter()
                .filter_map(|instance| {
                    storage
                        .get_substate_at_height(Executor::instance_record_key(*instance), height)
                        .flatten()
                })
                .filter_map(|record| Bytes::new(record).ok())
                .collect();
            GetInstanceRecordsResponse::new(
                Capped::new(records).expect("no more answers than the request named"),
            )
        },
    );

    // ── witness_history.request → snap-sync accumulator seeding ──

    let pending_chain = Arc::clone(&io.pending_chain);
    register_served::<GetWitnessHistoryRequest, _>(&*process.network, shard, move |req| {
        serve_witness_history_request(&pending_chain, req)
    });

    // ── provision.request → serve from local store ───────────────
    //
    // Dedup + cache: the proof for (block_height, target_shard) is
    // deterministic, and many validators request the same provisions.
    // Without dedup each request regenerates the merkle proof, and under
    // load the redundant generations per height thrash the CPU.

    let pending_chain = Arc::clone(&io.pending_chain);
    let topology_snapshot = process.topology_snapshot.clone();
    let outbound_cache = Arc::clone(&io.caches.provision_store);
    let derivation = process.derivation();

    let provisions_flight = SingleFlight::new(
        PROVISION_CACHE_CAPACITY,
        MAX_WAITERS_PER_KEY,
        PRODUCER_WAIT_BUDGET,
    );

    register_served::<GetProvisionsRequest, _>(
        &*process.network,
        shard,
        move |req: &GetProvisionsRequest| {
            let height = req.height;

            // Outbound fast path: if we still hold the exact batch we
            // generated for this (source_block_height, target_shard),
            // rebuild the response from memory — no RocksDB regeneration,
            // no merkle-proof recomputation.
            if let Some(provisions) = outbound_cache.get_outbound(height, req.target_shard) {
                return GetProvisionResponse {
                    provisions: Some(provisions),
                };
            }

            let cache_key = (height.inner(), req.target_shard.inner());
            let provisions = match provisions_flight.get_or_produce(cache_key, || {
                serve_provision_request(
                    &pending_chain,
                    derivation.as_ref(),
                    shard,
                    topology_snapshot.load().shard_trie(),
                    req,
                )
                .provisions
            }) {
                Flight::Cached(provisions)
                | Flight::Joined(provisions)
                | Flight::Produced(provisions) => Some(provisions),
                Flight::Unavailable => None,
            };
            GetProvisionResponse { provisions }
        },
    );

    // ── local_provision.request → provision cache lookup ─────────

    let provision_store = Arc::clone(&io.caches.provision_store);
    let verified_headers = Arc::clone(&io.caches.verified_headers);
    register_served::<GetLocalProvisionsRequest, _>(&*process.network, shard, move |req| {
        serve_local_provisions_request(&provision_store, &verified_headers, req)
    });

    // ── finalization.request → cache lookup + pending_chain fallback ─

    let fw_cache = Arc::clone(&io.caches.finalization);
    let pending_chain = Arc::clone(&io.pending_chain);
    register_served::<GetFinalizationsRequest, _>(&*process.network, shard, move |req| {
        serve_finalizations_request(&pending_chain, &fw_cache, req)
    });

    // ── remote_header.request → range header sync ───────────────────

    let pending_chain = Arc::clone(&io.pending_chain);
    register_served::<GetRemoteHeadersRequest, _>(&*process.network, shard, move |req| {
        serve_remote_headers_request(&pending_chain, shard, req)
    });

    // ── beacon.shard_witnesses.request → witness proof serve ────────
    //
    // Beacon validators outside this shard's committee pull
    // accumulator leaves + inclusion proofs anchored at a
    // specific committed block. Pure CPU + storage read; no
    // dedup until traffic profiling shows it's worth it.

    let pending_chain = Arc::clone(&io.pending_chain);
    process
        .network
        .register_request_handler::<GetShardWitnessesRequest>(shard, move |req| {
            serve_shard_witnesses_request(&pending_chain, &req)
        });

    // ── settled_txs.request → terminated-shard settled window list ──
    //
    // A counterpart resolving this shard's settled set across a split
    // boundary names its terminal block; we serve the complete settled-transaction
    // window list, which the counterpart accepts against the beacon-attested
    // settled-transaction root. The window floor comes off the live topology
    // projection so the served window matches the one the terminal's
    // proposer attested.
    let pending_chain = Arc::clone(&io.pending_chain);
    let topology_snapshot = process.topology_snapshot().clone();
    // The walk behind an answer is the terminating shard's whole
    // scheduled window, and the chain's own memo only extends — so a
    // request below its coverage re-walks the span in full. One
    // reconstruction per terminal serves every peer still asking.
    let settled_txs_cache = Arc::new(SettledTxsCache::default());
    register_served::<GetSettledTxsRequest, _>(&*process.network, shard, move |req| {
        let window_floor = topology_snapshot.load().settled_window_floor(shard);
        serve_settled_txs_request(&pending_chain, &settled_txs_cache, window_floor, req)
    });

    // ── state_proof.request → proof of keys at a committed height ──
    //
    // A shard holding an escrow a core here never claimed asks whether
    // this shard committed the transaction, and a split's right child asks
    // a terminated parent whether it did, each against one of our headers
    // it has commit-proved. The proof is checked against that header's
    // root on the requester's side, so nothing here is trusted; a
    // height outside the JMT's history answers `not_found` and the
    // requester rotates.
    let pending_chain = Arc::clone(&io.pending_chain);
    register_served::<GetStateProofRequest, _>(&*process.network, shard, move |req| {
        serve_state_proof_request(&pending_chain, req)
    });

    // ── cells.request → the cells a declaration reaches ───────────
    //
    // A node assembling a preview for a transaction whose declared
    // cells live on shards it does not serve asks each of them for the
    // points and intervals the declaration names. Checked against the
    // root of a header the requester commit-proved, so any node of this
    // shard may answer and none is trusted with the verdict.
    let pending_chain = Arc::clone(&io.pending_chain);
    register_served::<GetCellsRequest, _>(&*process.network, shard, move |req| {
        serve_cells_request(&pending_chain, req)
    });

    // ── block.proposal.request → this shard's admitted proposals ─
    let proposals = Arc::clone(&io.consensus.proposals);
    process
        .network
        .register_request_handler::<GetProposalRequest>(shard, move |req| proposals.serve(&req));

    // ── beacon.proposal.request → process-level serve cache ──────
    let proposal_cache = Arc::clone(&process.dispatch_handles.beacon_proposal_cache);
    process
        .network
        .register_request_handler::<GetBeaconProposalRequest>(shard, move |req| {
            proposal_cache.serve(&req)
        });

    // ── beacon.candidate.request → process-level serve cache ─────
    let candidate_cache = Arc::clone(&process.dispatch_handles.beacon_candidate_cache);
    process
        .network
        .register_request_handler::<GetBeaconCandidateRequest>(shard, move |req| {
            candidate_cache.serve(&req)
        });

    // ── beacon.block.request → committed beacon block by epoch ──
    let beacon_storage = Arc::clone(&process.beacon_storage);
    process
        .network
        .register_request_handler::<GetBeaconBlockRequest>(shard, move |req| {
            serve_beacon_block_request(beacon_storage.as_ref(), &req)
        });
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crossbeam::channel::{Receiver, unbounded};
    use hyperscale_core::ProtocolEvent;
    use hyperscale_hbor::{Capped, to_vec as hbor_to_vec};
    use hyperscale_network::{HandlerRegistry, PeerId, Provenance, Verdict};
    use hyperscale_types::network::gossip::{CertifiedBlockHeaderGossip, TransactionGossip};
    use hyperscale_types::network::notification::{
        BlockHeaderNotification, ReadySignalNotification,
    };
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        BlockHeader, BlockHeaderParts, BlockHeight, BlockManifest, BlockProposalMessage,
        CertifiedBlockHeader, ChainOrigin, ConsensusSignature, NetworkDefinition, NetworkMessage,
        QuorumCertificate, ReadySignal, ShardId, Verifiable, Verified, WeightedTimestamp,
        signed_bytes,
    };

    use crate::event::{
        HostEvent, NETWORK_LANE_CAPACITY, NetworkLaneReceiver, ShardInbox, ShardScopedInput,
        network_lane,
    };
    use crate::shard::push_shard_input;
    use crate::shard::test_host::{CountingVerifier, Fixture, Host, SHARD, loop_of};

    /// A message from some peer.
    const PEER: Provenance = Provenance::Peer(PeerId::new(1));

    fn gossip(seed: u8) -> TransactionGossip {
        TransactionGossip::new(Capped::from_array([(test_transaction(seed))]))
    }

    /// `gossip` as a peer's copy reaches the registry: as wire bytes.
    fn from_peer(registry: &HandlerRegistry, gossip: &TransactionGossip) -> Option<Verdict> {
        from(registry, gossip, PEER)
    }

    /// `gossip` as the copy `provenance` names reaches the registry.
    fn from(
        registry: &HandlerRegistry,
        gossip: &TransactionGossip,
        provenance: Provenance,
    ) -> Option<Verdict> {
        let handler = registry
            .get_gossip(TransactionGossip::message_type_id())
            .expect("transaction gossip has a handler");
        handler(
            hbor_to_vec(gossip).expect("gossip encodes"),
            Some(SHARD),
            provenance,
        )
    }

    fn ready_signal(fix: &Fixture, shard: ShardId) -> ReadySignalNotification {
        let (validator, signer) = fix.identity(2);
        ReadySignalNotification::new(
            ReadySignal::sign(
                &NetworkDefinition::simulator(),
                validator,
                shard,
                WeightedTimestamp::ZERO,
                WeightedTimestamp::ZERO,
                signer.as_ref(),
            )
            .expect("the validator's key signs"),
        )
    }

    /// Gossip from a peer within its share that finds its shard's network
    /// lane full is refused as gossip this host has no room for, at once
    /// rather than once the lane has room, and the lane being full keeps no
    /// continuation of the loop's own off its internal lane.
    #[test]
    fn a_full_network_lane_refuses_gossip_and_keeps_internal_inputs() {
        let fix = Fixture::new();
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
        let (internal_tx, internal) = unbounded();
        let (lane, network) = network_lane(2);
        let (beacon_tx, _beacon) = unbounded();
        let mut host = fix.host_with_inbox(
            Arc::clone(&registry),
            beacon_tx,
            ShardInbox::new(internal_tx, lane),
        );
        while internal.try_recv().is_ok() {}

        let other = Provenance::Peer(PeerId::new(2));
        assert_eq!(from_peer(&registry, &gossip(1)), Some(Verdict::Accept));
        assert_eq!(from_peer(&registry, &gossip(3)), Some(Verdict::Accept));
        assert_eq!(
            from(&registry, &gossip(2), other),
            Some(Verdict::Busy),
            "gossip past the lane's bound is refused, not queued",
        );
        assert_eq!(network.len(), 2);

        push_shard_input(
            loop_of(&mut host).event_sender(),
            SHARD,
            ShardScopedInput::FetchTick,
        );
        assert!(
            internal
                .try_iter()
                .any(|event| matches!(event, HostEvent::Shard(_, ShardScopedInput::FetchTick))),
            "the loop's own continuation lands past a full network lane",
        );

        let _ = network.try_recv();
        assert_eq!(
            from(&registry, &gossip(2), other),
            Some(Verdict::Accept),
            "a refused copy is taken once the lane has room",
        );
    }

    /// A peer that fills its shard's network lane on its own has its next
    /// gossip refused as past its share once another peer has been refused
    /// room, which its transport charges it for; the other peer, within
    /// its share, is refused for want of room, for nothing. The room a
    /// drain frees goes to the other peer.
    #[test]
    fn a_peer_holding_the_lane_past_its_share_is_refused_as_ignored() {
        let fix = Fixture::new();
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
        let (internal_tx, internal) = unbounded();
        let (lane, network) = network_lane(2);
        let (beacon_tx, _beacon) = unbounded();
        let _host = fix.host_with_inbox(
            Arc::clone(&registry),
            beacon_tx,
            ShardInbox::new(internal_tx, lane),
        );
        while internal.try_recv().is_ok() {}
        let flooder = Provenance::Peer(PeerId::new(1));
        let honest = Provenance::Peer(PeerId::new(2));

        assert_eq!(from(&registry, &gossip(1), flooder), Some(Verdict::Accept));
        assert_eq!(from(&registry, &gossip(2), flooder), Some(Verdict::Accept));
        assert_eq!(
            from(&registry, &gossip(3), honest),
            Some(Verdict::Busy),
            "a peer within its share finds the lane full",
        );
        assert_eq!(
            from(&registry, &gossip(4), flooder),
            Some(Verdict::Ignore),
            "a peer holding the lane past its share is refused as ignored",
        );

        assert!(network.try_recv().is_some());
        assert_eq!(
            from(&registry, &gossip(4), flooder),
            Some(Verdict::Busy),
            "the room a drain frees is not the flooder's",
        );
        assert_eq!(from(&registry, &gossip(3), honest), Some(Verdict::Accept));
    }

    /// What the host sends its own co-hosted shards lands on their internal
    /// lane, however full the network lane peers fill is.
    #[test]
    fn the_hosts_own_messages_land_past_a_full_network_lane() {
        let fix = Fixture::new();
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
        let (internal_tx, internal) = unbounded();
        let (lane, network) = network_lane(1);
        let (beacon_tx, _beacon) = unbounded();
        let _host = fix.host_with_inbox(
            Arc::clone(&registry),
            beacon_tx,
            ShardInbox::new(internal_tx, lane),
        );
        while internal.try_recv().is_ok() {}
        assert_eq!(from_peer(&registry, &gossip(1)), Some(Verdict::Accept));
        assert_eq!(network.len(), 1, "the network lane is full");

        assert!(registry.local_dispatch_notification(&ready_signal(&fix, SHARD)));
        assert_eq!(
            registry.local_dispatch_gossip(&gossip(2), Some(SHARD)),
            Some(Verdict::Accept),
        );
        let landed: Vec<HostEvent> = internal.try_iter().collect();
        assert!(
            landed.iter().any(|event| matches!(
                event,
                HostEvent::Shard(_, ShardScopedInput::Protocol(event))
                    if matches!(**event, ProtocolEvent::ReadySignalReceived { .. })
            )),
            "the host's own notification lands",
        );
        assert!(
            landed.iter().any(|event| matches!(
                event,
                HostEvent::Shard(_, ShardScopedInput::TransactionGossipReceived { .. })
            )),
            "the host's own gossip lands",
        );
        assert_eq!(network.len(), 1, "nothing of the host's joins the lane");
    }
    /// A ready signal reaches the hosted shards on its shard's trie line,
    /// the splitting parent of the child it readies among them, and no
    /// hosted shard off that line.
    #[test]
    fn a_ready_signal_reaches_only_the_shards_on_its_line() {
        let fix = Fixture::new();
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
        let (internal_tx, _internal) = unbounded();
        let (lane, network) = network_lane(NETWORK_LANE_CAPACITY);
        let (beacon_tx, _beacon) = unbounded();
        let _host = fix.host_with_inbox(
            Arc::clone(&registry),
            beacon_tx,
            ShardInbox::new(internal_tx, lane),
        );
        let handler = registry
            .get_notification(ReadySignalNotification::message_type_id())
            .expect("ready signals have a handler");
        let (left, right) = SHARD.children();
        let sibling = ShardId::leaf(1, 1);
        let delivered = |shard: ShardId| {
            let _ = handler(
                hbor_to_vec(&ready_signal(&fix, shard)).expect("signal encodes"),
                PEER,
            );
            network
                .try_iter()
                .filter(|event| {
                    matches!(
                        event,
                        HostEvent::Shard(hosted, ShardScopedInput::Protocol(event))
                            if *hosted == SHARD
                                && matches!(**event, ProtocolEvent::ReadySignalReceived { .. })
                    )
                })
                .count()
        };

        assert_eq!(delivered(SHARD), 1, "a signal for the shard itself");
        assert_eq!(delivered(left), 1, "an observer readying a child");
        assert_eq!(delivered(right), 1, "an observer readying the other child");
        assert_eq!(
            delivered(ShardId::ROOT),
            1,
            "a keeper readying the merged parent"
        );
        assert_eq!(delivered(sibling), 0, "a signal for a shard off the line");
    }

    /// A host over `verifier`, with its shard's internal and network lanes.
    fn host_counting(
        fix: &Fixture,
        verifier: &Arc<CountingVerifier>,
    ) -> (
        Arc<HandlerRegistry>,
        Host,
        Receiver<HostEvent>,
        NetworkLaneReceiver,
    ) {
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
        let (internal_tx, internal) = unbounded();
        let (lane, network) = network_lane(NETWORK_LANE_CAPACITY);
        let (beacon_tx, _beacon) = unbounded();
        let host = fix.host_with_inbox_verifying(
            Arc::clone(&registry),
            beacon_tx,
            ShardInbox::new(internal_tx, lane),
            Arc::clone(verifier) as _,
        );
        while internal.try_recv().is_ok() {}
        (registry, host, internal, network)
    }

    /// `committee[proposer]`'s proposal at height 1 of `SHARD`, signed by
    /// `committee[key]`.
    fn proposal(fix: &Fixture, proposer: usize, key: usize) -> BlockHeaderNotification {
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: SHARD,
            height: BlockHeight::new(1),
            proposer: fix.identity(proposer).0,
            ..Default::default()
        });
        let msg = signed_bytes(
            &BlockProposalMessage {
                shard_group: SHARD,
                height: header.height(),
                round: header.round(),
                block_hash: header.hash(),
            },
            &NetworkDefinition::simulator(),
        );
        let signature = fix.identity(key).1.sign(&msg).expect("the key signs");
        BlockHeaderNotification::new(header, BlockManifest::default(), signature)
    }

    fn proposals(lane: impl Iterator<Item = HostEvent>) -> usize {
        lane.filter(|event| {
            matches!(
                event,
                HostEvent::Shard(_, ShardScopedInput::ProposalReceived { .. })
            )
        })
        .count()
    }

    /// The host's own proposal reaches its shard without a signature check;
    /// a peer's copy of it is checked, and a forged one refused.
    #[test]
    fn the_hosts_own_proposal_lands_unchecked_and_a_peers_is_checked() {
        let fix = Fixture::new();
        let verifier = Arc::new(CountingVerifier::default());
        let (registry, _host, internal, network) = host_counting(&fix, &verifier);
        let handler = registry
            .get_notification(BlockHeaderNotification::message_type_id())
            .expect("block headers have a handler");

        assert!(registry.local_dispatch_notification(&proposal(&fix, 1, 1)));
        assert_eq!(
            verifier.checked(),
            0,
            "the host's own proposal is not checked"
        );
        assert_eq!(
            proposals(internal.try_iter()),
            1,
            "the host's own proposal lands"
        );

        let wire = |note: &BlockHeaderNotification| hbor_to_vec(note).expect("proposal encodes");
        assert_eq!(handler(wire(&proposal(&fix, 1, 1)), PEER), Verdict::Accept);
        assert_eq!(verifier.checked(), 1, "a peer's copy is checked");
        assert_eq!(proposals(network.try_iter()), 1, "a peer's copy lands");

        assert_eq!(handler(wire(&proposal(&fix, 1, 2)), PEER), Verdict::Reject);
        assert_eq!(proposals(network.try_iter()), 0, "a forged copy is refused");
    }

    /// The host's own certified header reaches its other shards as the
    /// verified header it certified: no sender to authenticate, no
    /// signature checked, no batch to wait in.
    #[test]
    fn the_hosts_own_certified_header_lands_verified() {
        let fix = Fixture::new();
        let verifier = Arc::new(CountingVerifier::default());
        let (registry, _host, internal, network) = host_counting(&fix, &verifier);
        let source = ShardId::leaf(1, 1);
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: source,
            height: BlockHeight::new(1),
            proposer: fix.identity(1).0,
            ..Default::default()
        });
        let qc = QuorumCertificate::genesis(source, ChainOrigin::root(WeightedTimestamp::ZERO));
        let certified = Verified::new_unchecked_for_test(CertifiedBlockHeader::new(header, qc));
        let gossip = CertifiedBlockHeaderGossip {
            certified_header: Verifiable::from(certified),
            sender: fix.identity(1).0,
            sender_signature: ConsensusSignature::ZERO,
        };

        assert_eq!(
            registry.local_dispatch_gossip(&gossip, None),
            Some(Verdict::Accept)
        );
        assert_eq!(verifier.checked(), 0);
        let landed: Vec<HostEvent> = internal.try_iter().collect();
        assert!(
            landed.iter().any(|event| matches!(
                event,
                HostEvent::Shard(shard, ShardScopedInput::Protocol(event))
                    if *shard == SHARD
                        && matches!(**event, ProtocolEvent::VerifiedRemoteHeaderReceived { .. })
            )),
            "the host's own header lands verified",
        );
        assert_eq!(network.len(), 0);
    }
}
