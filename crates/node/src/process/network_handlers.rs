//! Network handler registration (gossip, notifications, requests).

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::gossip::{CertifiedBlockHeaderGossip, TransactionGossip};
use hyperscale_types::network::notification::beacon::{
    BeaconProposalNotification, PcVote1Notification, PcVote2Notification, PcVote3Notification,
    SpcEmptyViewMsgNotification, SpcNewCommitNotification, SpcNewViewNotification,
};
use hyperscale_types::network::notification::{
    BlockHeaderNotification, BlockVoteNotification, ExecutionCertificatesNotification,
    ExecutionVotesNotification, ProvisionsNotification, ReadySignalNotification,
    TimeoutNotification,
};
use hyperscale_types::network::request::beacon::{
    GetBeaconBlockRequest, GetBeaconProposalRequest, GetShardWitnessesRequest,
};
use hyperscale_types::network::request::{
    GetExecutionCertsRequest, GetFinalizedWavesRequest, GetLocalProvisionsRequest,
};
use hyperscale_types::network::response::GetProvisionResponse;
use hyperscale_types::{ExecutionCertificate, ShardId, Verifiable, ready_signal_message};
use tracing::warn;

use crate::beacon::gossip::register_beacon_gossip_handlers;
use crate::event::ShardScopedInput;
use crate::host::NodeHost;
use crate::process::ProcessIo;
use crate::shard::ShardIo;
use crate::shard::verify::{
    resolve_sender_key, verify_bls_with_metrics, verify_signed_by_committee,
    verify_signed_by_proposer,
};
use crate::shard_loop::{push_protocol_event, push_shard_input};

impl<S, N, D> NodeHost<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Register per-type request handlers for every hosted shard.
    pub(crate) fn register_request_handler(&self) {
        let shards: Vec<ShardId> = self.hosted_shards().collect();
        for shard in shards {
            register_shard_request_handlers(&self.process, self.shard_io(shard), shard);
        }
    }

    /// Register gossip handlers for broadcast message types (transactions
    /// and committed block headers).
    ///
    /// Both handler closures see a single `(message, target_shard)` pair —
    /// the network framework computes the per-vnode fan-out from each
    /// type's [`GossipMessage::SCOPE`] and [`GossipMessage::source_shard`].
    /// Closures here just translate into `ShardScopedInput`.
    #[allow(clippy::too_many_lines)] // single registration table; one closure per gossip type
    pub(crate) fn register_gossip_handlers(&self) {
        use hyperscale_network::GossipVerdict;

        // ── transaction.gossip → ShardScopedInput::TransactionGossipReceived ─

        let senders = self.process.shard_event_senders.clone();
        let canonical_txs = Arc::clone(&self.process.canonical_txs);
        self.process
            .network
            .register_gossip_handler::<TransactionGossip>(
                move |gossip: TransactionGossip, shard: ShardId| -> GossipVerdict {
                    let senders = senders.load();
                    let Some(tx) = senders.get(&shard) else {
                        warn!(
                            shard = shard.inner(),
                            "Dropping tx gossip: shard not hosted"
                        );
                        return GossipVerdict::Reject;
                    };
                    for transaction in gossip.transactions.into_inner() {
                        // A cross-shard tx arrives once per hosted shard
                        // topic, each a fresh decode; canonicalizing here
                        // lets the shards share one validation verdict.
                        let transaction = canonical_txs.canonicalize(&transaction);
                        push_shard_input(
                            tx,
                            shard,
                            ShardScopedInput::TransactionGossipReceived { tx: transaction },
                        );
                    }
                    GossipVerdict::Accept
                },
            );

        // ── block.committed → ShardScopedInput::CommittedBlockGossipReceived ─
        //
        // The framework already filters out the header's source shard,
        // so `target_shard` here is a hosted shard that needs this
        // header for cross-shard provisioning bookkeeping.

        let senders = self.process.shard_event_senders.clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_gossip_handler::<CertifiedBlockHeaderGossip>(
                move |gossip: CertifiedBlockHeaderGossip, target_shard: ShardId| -> GossipVerdict {
                    let senders = senders.load();
                    let Some(tx) = senders.get(&target_shard) else {
                        warn!(
                            target_shard = target_shard.inner(),
                            "Dropping certified header gossip: shard not hosted"
                        );
                        return GossipVerdict::Reject;
                    };
                    let sender = gossip.sender;
                    let header_shard = gossip.certified_header.header().shard_id();
                    let topo = topology.load();

                    let Some(public_key) =
                        resolve_sender_key(&topo, sender, header_shard, "certified header")
                    else {
                        return GossipVerdict::Reject;
                    };

                    push_shard_input(
                        tx,
                        target_shard,
                        ShardScopedInput::CommittedBlockGossipReceived {
                            certified_header: gossip.certified_header,
                            sender,
                            public_key,
                            sender_signature: gossip.sender_signature,
                        },
                    );
                    GossipVerdict::Accept
                },
            );

        // Beacon gossip (beacon.block per-shard + host-level pool route +
        // beacon.skip_request) lives in `crate::beacon::gossip` — the closures
        // capture only the senders, the pool channel, and the route gate.
        let route_active = self.process.beacon_route_active();
        register_beacon_gossip_handlers(
            &*self.process.network,
            &self.process.shard_event_senders,
            &self.process.beacon_event_sender,
            &route_active,
        );
    }

    /// Register notification handlers for protocol messages sent via unicast
    /// to known committee members.
    #[allow(clippy::too_many_lines)] // single registration table; one closure per notification type
    pub(crate) fn register_notification_handlers(&self) {
        // ── block.vote → ProtocolEvent::{Verified,Unverified}BlockVoteReceived ──
        //
        // `BlockVote.shard_id()` is the shard whose consensus the
        // vote is for; with cross-shard hosting that selects which of
        // this host's vnodes the event fans out to. Drop early if the
        // vote targets a shard we don't host.
        //
        // Wire decode lands the wrapper as `Verifiable::Unverified`;
        // local-dispatched sends from a colocated voter arrive already
        // verified and skip the state machine's BLS round-trip.

        let senders = self.process.shard_event_senders.clone();
        self.process
            .network
            .register_notification_handler::<BlockVoteNotification>(
                move |gossip: BlockVoteNotification| {
                    let shard = gossip.vote.shard_id();
                    let senders = senders.load();
                    let Some(tx) = senders.get(&shard) else {
                        warn!(
                            target_shard = shard.inner(),
                            "Dropping block vote: shard not hosted"
                        );
                        return;
                    };
                    let event = match gossip.vote.into_verified() {
                        Ok(vote) => ProtocolEvent::VerifiedBlockVoteReceived { vote },
                        Err(vote) => ProtocolEvent::UnverifiedBlockVoteReceived { vote },
                    };
                    push_protocol_event(tx, shard, event);
                },
            );

        // ── shard.timeout → ProtocolEvent::{Verified,Unverified}TimeoutReceived ─
        let senders = self.process.shard_event_senders.clone();
        self.process
            .network
            .register_notification_handler::<TimeoutNotification>(
                move |gossip: TimeoutNotification| {
                    let shard = gossip.timeout.shard_id();
                    let senders = senders.load();
                    let Some(tx) = senders.get(&shard) else {
                        warn!(
                            target_shard = shard.inner(),
                            "Dropping timeout: shard not hosted"
                        );
                        return;
                    };
                    let event = match gossip.timeout.into_verified() {
                        Ok(timeout) => ProtocolEvent::VerifiedTimeoutReceived { timeout },
                        Err(timeout) => ProtocolEvent::UnverifiedTimeoutReceived { timeout },
                    };
                    push_protocol_event(tx, shard, event);
                },
            );

        // ── block.header → verify proposer sig, then ProtocolEvent::BlockHeaderReceived ─

        let senders = self.process.shard_event_senders.clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_notification_handler::<BlockHeaderNotification>(
                move |gossip: BlockHeaderNotification| {
                    let shard = gossip.header.shard_id();
                    let senders = senders.load();
                    let Some(tx) = senders.get(&shard) else {
                        warn!(
                            target_shard = shard.inner(),
                            "Dropping block header: shard not hosted"
                        );
                        return;
                    };
                    let topo = topology.load();
                    if !verify_signed_by_proposer(&topo, &gossip, "block_header", "block header") {
                        return;
                    }
                    let (header, manifest, _sig) = gossip.into_parts();
                    push_protocol_event(
                        tx,
                        shard,
                        ProtocolEvent::BlockHeaderReceived { header, manifest },
                    );
                },
            );

        // ── provisions.broadcast → ProtocolEvent::{Verified,Unverified}ProvisionsReceived ─
        //
        // Wire decode lands the wrapper as `Verifiable::Unverified`;
        // local-dispatched sends from a colocated source-shard proposer
        // arrive already verified and skip the state machine's
        // `Action::VerifyProvisions` dispatch. The verified arm also
        // skips the envelope BLS check — same-process delivery means
        // the sender is us, and sender identity is already implicit.

        let senders = self.process.shard_event_senders.clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_notification_handler::<ProvisionsNotification>(
                move |notification: ProvisionsNotification| {
                    let target_shard = notification.provisions.target_shard();
                    // Drop provisions not destined for any hosted shard before
                    // paying the BLS verification cost.
                    let senders = senders.load();
                    let Some(tx) = senders.get(&target_shard) else {
                        warn!(
                            source_shard = notification.provisions.source_shard().inner(),
                            target_shard = target_shard.inner(),
                            "Dropping provisions notification: target_shard not hosted"
                        );
                        return;
                    };

                    let source_shard = notification.provisions.source_shard();
                    let event = if notification.provisions.is_verified() {
                        let verified = Arc::unwrap_or_clone(notification.provisions)
                            .into_verified()
                            .unwrap_or_else(|_| {
                                unreachable!("is_verified() guards the verified arm")
                            });
                        ProtocolEvent::VerifiedProvisionsReceived {
                            provisions: Arc::new(verified),
                        }
                    } else {
                        let topo = topology.load();
                        if !verify_signed_by_committee(
                            &topo,
                            source_shard,
                            &notification,
                            "state_provisions",
                            "state provision",
                        ) {
                            return;
                        }
                        let raw = Arc::unwrap_or_clone(notification.provisions).into_unverified();
                        ProtocolEvent::UnverifiedProvisionsReceived {
                            provisions: Arc::new(raw),
                        }
                    };
                    push_protocol_event(tx, target_shard, event);
                },
            );

        // ── execution.vote.batch → verify sender sig, then ProtocolEvent::UnverifiedExecutionVoteReceived ─

        let senders = self.process.shard_event_senders.clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_notification_handler::<ExecutionVotesNotification>(
                move |batch: ExecutionVotesNotification| {
                    if batch.votes.is_empty() {
                        return;
                    }

                    // Votes in a batch all carry the same shard (sender's
                    // local shard) by construction. Use the first vote's
                    // shard to identify the target hosted shard and gate
                    // before paying the BLS verification cost.
                    let target_shard = batch.votes[0].shard_id();
                    let senders = senders.load();
                    let Some(tx) = senders.get(&target_shard) else {
                        warn!(
                            target_shard = target_shard.inner(),
                            "Dropping execution vote batch: shard not hosted"
                        );
                        return;
                    };

                    let topo = topology.load();
                    if !verify_signed_by_committee(
                        &topo,
                        target_shard,
                        &batch,
                        "exec_vote_batch",
                        "execution vote batch",
                    ) {
                        return;
                    }

                    // Wire decode lands each vote as `Verifiable::Unverified`;
                    // local-dispatched batches from a colocated voter arrive
                    // already verified and skip the state machine's BLS
                    // round-trip.
                    for vote in batch.into_votes() {
                        let event = match vote.into_verified() {
                            Ok(vote) => ProtocolEvent::VerifiedExecutionVoteReceived { vote },
                            Err(vote) => ProtocolEvent::UnverifiedExecutionVoteReceived { vote },
                        };
                        push_protocol_event(tx, target_shard, event);
                    }
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
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_notification_handler::<ExecutionCertificatesNotification>(
                move |batch: ExecutionCertificatesNotification| {
                    if batch.certificates.is_empty() {
                        return;
                    }

                    let sender = batch.sender;
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
                        return;
                    }
                    let topo = topology.load();
                    // Sender signed with source_shard (their local shard), not our local shard
                    if !verify_signed_by_committee(
                        &topo,
                        source_shard,
                        &batch,
                        "exec_cert_batch",
                        "execution certificate batch",
                    ) {
                        return;
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
                    for (hosted_shard, tx) in senders.load().iter() {
                        push_protocol_event(
                            tx,
                            *hosted_shard,
                            ProtocolEvent::ExecutionCertificatesReceived {
                                certificates: certificates.clone(),
                            },
                        );
                    }
                },
            );

        // ── ready_signal → verify sender BLS sig, then ProtocolEvent::ReadySignalReceived ─
        //
        // The signal doesn't carry shard provenance — its only identity
        // is the sender's `validator_id`. Fan out to every hosted shard
        // and let each pool drop the signal if the sender isn't in that
        // shard's committee.

        let senders = self.process.shard_event_senders.clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_notification_handler::<ReadySignalNotification>(
                move |notification: ReadySignalNotification| {
                    let topo = topology.load();
                    let signal = notification.signal;
                    let sender = signal.validator_id();
                    let Some(public_key) = topo.public_key(sender) else {
                        warn!(
                            sender = sender.inner(),
                            "Dropping ready signal: unknown sender"
                        );
                        return;
                    };
                    let msg = ready_signal_message(
                        topo.network(),
                        sender,
                        signal.wt_window_start(),
                        signal.wt_window_end(),
                    );
                    if !verify_bls_with_metrics(&msg, &public_key, &signal.sig(), "ready_signal") {
                        warn!(
                            sender = sender.inner(),
                            "Ready signal BLS verify failed — dropping"
                        );
                        return;
                    }
                    for (hosted_shard, tx) in senders.load().iter() {
                        push_protocol_event(
                            tx,
                            *hosted_shard,
                            ProtocolEvent::ReadySignalReceived {
                                signal: signal.clone(),
                            },
                        );
                    }
                },
            );

        // ── beacon.proposal → Unverified/VerifiedBeaconProposalReceived ──
        //
        // Beacon-committee unicast. Fan to every hosted shard's
        // vnodes; each vnode's coordinator decides admission. Wire
        // decode lands the wrapper as `Unverified`; local-dispatched
        // sends preserve the `Verified` marker. The process-level
        // serve cache takes a copy (VRF-verified here when the wire
        // dropped the marker) so `GetBeaconProposalRequest` is
        // answered without reading any coordinator's pool.
        let senders = self.process.shard_event_senders.clone();
        let proposal_cache = Arc::clone(&self.process.dispatch_handles.beacon_proposal_cache);
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_notification_handler::<BeaconProposalNotification>(
                move |gossip: BeaconProposalNotification| {
                    let from = gossip.sender;
                    let epoch = gossip.epoch;
                    if let Some(sender_pk) = topology.load().public_key(from) {
                        proposal_cache.admit_wire(from, epoch, &gossip.proposal, sender_pk);
                    }
                    let event = match Arc::unwrap_or_clone(gossip.proposal).into_verified() {
                        Ok(verified) => ProtocolEvent::VerifiedBeaconProposalReceived {
                            from,
                            epoch,
                            proposal: Arc::new(verified),
                        },
                        Err(unverified) => ProtocolEvent::UnverifiedBeaconProposalReceived {
                            from,
                            epoch,
                            proposal: Arc::new(unverified.into()),
                        },
                    };
                    for (hosted_shard, tx) in senders.load().iter() {
                        push_protocol_event(tx, *hosted_shard, event.clone());
                    }
                },
            );

        // ── beacon.pc.vote1/2/3 → Unverified/VerifiedPcVote{N}Received ──
        //
        // PC votes carry the wrapping `view` because the inner vote
        // doesn't encode its SPC view; the receiver routes by view.
        macro_rules! register_pc_vote_handler {
            ($note_ty:ty, $unv:ident, $ver:ident, $vote_ty:ty $(, $box:tt)?) => {{
                let senders = self.process.shard_event_senders.clone();
                self.process.network.register_notification_handler::<$note_ty>(
                    move |gossip: $note_ty| {
                        let view = gossip.view;
                        let event = match Arc::unwrap_or_clone(gossip.vote).into_verified() {
                            Ok(verified) => ProtocolEvent::$ver {
                                view,
                                vote: register_pc_vote_handler!(@wrap $($box)? verified),
                            },
                            Err(unverified) => ProtocolEvent::$unv {
                                view,
                                vote: register_pc_vote_handler!(@wrap $($box)? unverified.into()),
                            },
                        };
                        for (hosted_shard, tx) in senders.load().iter() {
                            push_protocol_event(tx, *hosted_shard, event.clone());
                        }
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
        // We verify the sig under the sender's pubkey before fanning in;
        // BLS check fails → drop (`verify_signed_by_proposer` already
        // warns).
        let senders = self.process.shard_event_senders.clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_notification_handler::<SpcNewViewNotification>(
                move |gossip: SpcNewViewNotification| {
                    let topo = topology.load();
                    if !verify_signed_by_proposer(&topo, &gossip, "spc_new_view", "SPC new view") {
                        return;
                    }
                    let from = gossip.sender;
                    let event = ProtocolEvent::SpcNewViewReceived {
                        from,
                        proposal: gossip.proposal,
                    };
                    for (hosted_shard, tx) in senders.load().iter() {
                        push_protocol_event(tx, *hosted_shard, event.clone());
                    }
                },
            );

        // ── beacon.spc.new_commit → ProtocolEvent::SpcNewCommitReceived ──
        let senders = self.process.shard_event_senders.clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_notification_handler::<SpcNewCommitNotification>(
                move |gossip: SpcNewCommitNotification| {
                    let topo = topology.load();
                    if !verify_signed_by_proposer(
                        &topo,
                        &gossip,
                        "spc_new_commit",
                        "SPC new commit",
                    ) {
                        return;
                    }
                    let from = gossip.sender;
                    let event = ProtocolEvent::SpcNewCommitReceived {
                        from,
                        msg: gossip.msg,
                    };
                    for (hosted_shard, tx) in senders.load().iter() {
                        push_protocol_event(tx, *hosted_shard, event.clone());
                    }
                },
            );

        // ── beacon.spc.empty_view → Unverified/VerifiedSpcEmptyViewReceived ──
        //
        // EmptyView is content-signed, so — like new_view/new_commit — we
        // authenticate the signer at the relay edge before the coordinator
        // keys a per-`(epoch, view, signer)` verification slot, blocking a
        // peer from squatting another validator's slot with a forged-signer
        // message. Locally-dispatched sends arrive with the `Verified`
        // marker and skip the check; the expensive embedded-QC3 verify
        // still runs async in the coordinator.
        let senders = self.process.shard_event_senders.clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_notification_handler::<SpcEmptyViewMsgNotification>(
                move |gossip: SpcEmptyViewMsgNotification| {
                    if !gossip.msg.is_verified() {
                        let topo = topology.load();
                        if !verify_signed_by_proposer(
                            &topo,
                            &gossip,
                            "spc_empty_view",
                            "SPC empty view",
                        ) {
                            return;
                        }
                    }
                    let event = match Arc::unwrap_or_clone(gossip.msg).into_verified() {
                        Ok(verified) => ProtocolEvent::VerifiedSpcEmptyViewReceived {
                            msg: Box::new(verified),
                        },
                        Err(unverified) => ProtocolEvent::UnverifiedSpcEmptyViewReceived {
                            msg: Arc::new(unverified.into()),
                        },
                    };
                    for (hosted_shard, tx) in senders.load().iter() {
                        push_protocol_event(tx, *hosted_shard, event.clone());
                    }
                },
            );
    }
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
    use std::collections::HashMap;
    use std::sync::Arc;

    use hyperscale_types::network::request::{
        GetBlockRequest, GetProvisionsRequest, GetRemoteHeadersRequest, GetSettledWavesRequest,
        GetStateRangeRequest, GetTransactionsRequest, GetWitnessHistoryRequest,
    };

    use crate::beacon::serve::serve_beacon_block_request;
    use crate::beacon::witness_serve::serve_shard_witnesses_request;
    use crate::bootstrap::state_range_serve::serve_state_range_request;
    use crate::bootstrap::witness_history_serve::serve_witness_history_request;
    use crate::shard::consensus::serve_block_request;
    use crate::shard::cross_shard::{
        serve_execution_certs_request, serve_finalized_waves_request,
        serve_local_provisions_request, serve_provision_request, serve_remote_headers_request,
        serve_settled_waves_request,
    };
    use crate::shard::mempool::serve_transaction_request;

    type ProvisionResponse = GetProvisionResponse;
    type ProvisionWaiter = Arc<(
        std::sync::Mutex<Option<ProvisionResponse>>,
        std::sync::Condvar,
    )>;

    struct InFlightSlot {
        waiter: ProvisionWaiter,
        waiters: usize,
    }

    struct ProvisionsRequestDedup {
        cache: std::collections::BTreeMap<(u64, u64), ProvisionResponse>,
        in_flight: HashMap<(u64, u64), InFlightSlot>,
    }

    // Single-flight guard: clears the `in_flight` slot and wakes waiters
    // when the producer's stack unwinds — including on panic, where the
    // explicit cleanup below would be skipped. Waiters treat a still-`None`
    // slot after wake as a failure response.
    struct InFlightGuard {
        dedup: Arc<std::sync::Mutex<ProvisionsRequestDedup>>,
        waiter: ProvisionWaiter,
        cache_key: (u64, u64),
    }
    impl Drop for InFlightGuard {
        fn drop(&mut self) {
            if let Ok(mut g) = self.dedup.lock() {
                g.in_flight.remove(&self.cache_key);
            }
            self.waiter.1.notify_all();
        }
    }

    // Cap how long a waiter blocks on a producer. Request handlers run on
    // tokio blocking-pool threads; without a bound, a stalled producer can
    // pin every waiter thread and eventually starve the pool. The guard
    // above already wakes waiters on producer panic — this bound covers
    // the rest (deadlock, deep stalls, runaway work).
    const PRODUCER_WAIT_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

    // Cap concurrent waiters on a single producer. Honest fan-out from
    // a remote committee can stack dozens of waiters on one (height,
    // shard) key; this cap covers that case while bounding the
    // blocking-pool footprint when a producer stalls. Waiters past
    // the cap return `None` immediately and let the caller retry —
    // by then the producer has typically published a result that the
    // cache fast path will serve.
    const MAX_WAITERS_PER_KEY: usize = 64;

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
    process
        .network
        .register_request_handler::<GetTransactionsRequest>(shard, move |req| {
            serve_transaction_request(&pending_chain, &tx_store, &req)
        });

    // ── state_range.request → snap-sync boundary serving ─────────

    let storage = Arc::clone(&io.storage);
    process
        .network
        .register_request_handler::<GetStateRangeRequest>(shard, move |req| {
            serve_state_range_request(&storage, &req)
        });

    // ── witness_history.request → snap-sync accumulator seeding ──

    let pending_chain = Arc::clone(&io.pending_chain);
    process
        .network
        .register_request_handler::<GetWitnessHistoryRequest>(shard, move |req| {
            serve_witness_history_request(&pending_chain, &req)
        });

    // ── provision.request → serve from local store ───────────────
    //
    // Dedup + cache: the proof for (block_height, target_shard) is
    // deterministic, and many validators request the same provisions.
    // Without dedup each request regenerates the merkle proof (~30ms),
    // and under load 40+ redundant generations per height cause CPU
    // thrashing.

    let pending_chain = Arc::clone(&io.pending_chain);
    let topology = process.topology_snapshot.clone();
    let outbound_cache = Arc::clone(&io.caches.provision_store);

    let dedup: Arc<std::sync::Mutex<ProvisionsRequestDedup>> =
        Arc::new(std::sync::Mutex::new(ProvisionsRequestDedup {
            cache: std::collections::BTreeMap::new(),
            in_flight: HashMap::new(),
        }));

    process
        .network
        .register_request_handler::<GetProvisionsRequest>(
            shard,
            move |req: GetProvisionsRequest| {
                let cache_key = (req.block_height.inner(), req.target_shard.inner());

                // Outbound fast path: if we still hold the exact batch we
                // generated for this (source_block_height, target_shard),
                // rebuild the response from memory — no RocksDB regeneration,
                // no merkle-proof recomputation.
                if let Some(provisions) =
                    outbound_cache.get_outbound(req.block_height, req.target_shard)
                {
                    record_fetch_response_sent("provision", provisions.transactions().len().max(1));
                    return GetProvisionResponse {
                        provisions: Some(provisions),
                    };
                }

                // Fast path: check cache or join an existing in-flight
                // computation. Reservation happens under `dedup` lock so
                // the per-key waiter cap is checked atomically with the
                // count increment.
                let waiter_to_join = {
                    let mut guard = dedup.lock().unwrap();
                    if let Some(cached) = guard.cache.get(&cache_key) {
                        if let Some(p) = &cached.provisions {
                            record_fetch_response_sent("provision", p.transactions().len().max(1));
                        }
                        return cached.clone();
                    }
                    if let Some(slot) = guard.in_flight.get_mut(&cache_key) {
                        if slot.waiters >= MAX_WAITERS_PER_KEY {
                            // Cap reached — return a soft failure so the
                            // caller can retry once the producer publishes;
                            // the cache fast path will then serve.
                            return GetProvisionResponse { provisions: None };
                        }
                        slot.waiters += 1;
                        Some(Arc::clone(&slot.waiter))
                    } else {
                        None
                    }
                };

                if let Some(waiter) = waiter_to_join {
                    let (lock, cvar) = &*waiter;
                    let wait_result =
                        cvar.wait_timeout_while(lock.lock().unwrap(), PRODUCER_WAIT_BUDGET, |r| {
                            r.is_none()
                        });
                    // Decrement the per-key waiter count regardless of how
                    // we left the wait (timeout, success, or producer drop).
                    // The producer's `InFlightGuard` may have already
                    // removed the slot, and a fresh producer may have
                    // inserted a new one under the same key — `ptr_eq`
                    // ensures we only decrement against the slot we
                    // actually joined.
                    if let Ok(mut g) = dedup.lock()
                        && let Some(slot) = g.in_flight.get_mut(&cache_key)
                        && Arc::ptr_eq(&slot.waiter, &waiter)
                    {
                        slot.waiters = slot.waiters.saturating_sub(1);
                    }
                    let (result, wait_outcome) = wait_result.unwrap();
                    if wait_outcome.timed_out() {
                        return GetProvisionResponse { provisions: None };
                    }
                    return result
                        .clone()
                        .unwrap_or(GetProvisionResponse { provisions: None });
                }

                // We're the producer — register the in-flight slot and let
                // the guard handle cleanup + waiter wake-up on every exit
                // path, including panic.
                let waiter: ProvisionWaiter = Arc::new((
                    std::sync::Mutex::new(None::<GetProvisionResponse>),
                    std::sync::Condvar::new(),
                ));
                dedup.lock().unwrap().in_flight.insert(
                    cache_key,
                    InFlightSlot {
                        waiter: Arc::clone(&waiter),
                        waiters: 0,
                    },
                );

                let _guard = InFlightGuard {
                    dedup: Arc::clone(&dedup),
                    waiter: Arc::clone(&waiter),
                    cache_key,
                };

                let response = serve_provision_request(
                    &pending_chain,
                    shard,
                    topology.load().shard_trie(),
                    &req,
                );

                if response.provisions.is_some() {
                    let mut g = dedup.lock().unwrap();
                    g.cache.insert(cache_key, response.clone());
                    // Evict oldest entry (keep last 256)
                    if g.cache.len() > 256 {
                        g.cache.pop_first();
                    }
                }

                // Publish the result before the guard's notify_all fires.
                *waiter.0.lock().unwrap() = Some(response.clone());

                response
            },
        );

    // ── local_provision.request → provision cache lookup ─────────

    let provision_store = Arc::clone(&io.caches.provision_store);
    let verified_headers = Arc::clone(&io.caches.verified_headers);
    process
        .network
        .register_request_handler::<GetLocalProvisionsRequest>(shard, move |req| {
            serve_local_provisions_request(&provision_store, &verified_headers, &req)
        });

    // ── finalized_wave.request → cache lookup + pending_chain fallback ─

    let fw_cache = Arc::clone(&io.caches.finalized_wave);
    let pending_chain = Arc::clone(&io.pending_chain);
    process
        .network
        .register_request_handler::<GetFinalizedWavesRequest>(shard, move |req| {
            serve_finalized_waves_request(&pending_chain, &fw_cache, &req)
        });

    // ── execution_cert.request → cert store lookup ────────────────

    let exec_cert_store = Arc::clone(&io.caches.exec_cert_store);
    let pending_chain = Arc::clone(&io.pending_chain);
    process
        .network
        .register_request_handler::<GetExecutionCertsRequest>(shard, move |req| {
            serve_execution_certs_request(&pending_chain, &exec_cert_store, &req)
        });

    // ── remote_header.request → range header sync ───────────────────

    let pending_chain = Arc::clone(&io.pending_chain);
    process
        .network
        .register_request_handler::<GetRemoteHeadersRequest>(shard, move |req| {
            serve_remote_headers_request(&pending_chain, shard, &req)
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

    // ── settled_waves.request → terminated-shard settled window list ──
    //
    // A counterpart resolving this shard's settled set across a split
    // boundary names its terminal block; we serve the complete settled-wave
    // window list, which the counterpart accepts against the beacon-attested
    // settled-waves root.
    let pending_chain = Arc::clone(&io.pending_chain);
    process
        .network
        .register_request_handler::<GetSettledWavesRequest>(shard, move |req| {
            serve_settled_waves_request(&pending_chain, &req)
        });

    // ── beacon.proposal.request → process-level serve cache ──────
    let proposal_cache = Arc::clone(&process.dispatch_handles.beacon_proposal_cache);
    process
        .network
        .register_request_handler::<GetBeaconProposalRequest>(shard, move |req| {
            proposal_cache.serve(&req)
        });

    // ── beacon.block.request → committed beacon block by epoch ──
    let beacon_storage = Arc::clone(&process.beacon_storage);
    process
        .network
        .register_request_handler::<GetBeaconBlockRequest>(shard, move |req| {
            serve_beacon_block_request(beacon_storage.as_ref(), &req)
        });
}
