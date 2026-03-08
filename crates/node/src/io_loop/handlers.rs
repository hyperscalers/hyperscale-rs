//! Network handler registration (gossip, notifications, requests).

use super::verify::{resolve_sender_key, verify_bls_with_metrics, verify_sender_signature};
use super::IoLoop;
use hyperscale_core::{NodeInput, ProtocolEvent};
use hyperscale_dispatch::Dispatch;
use hyperscale_messages::{
    BlockHeaderNotification, BlockVoteNotification, ExecutionCertificatesNotification,
    ExecutionVotesNotification, TransactionCertificateNotification, TransactionGossip,
};
use hyperscale_network::Network;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};
use std::sync::Arc;
use tracing::warn;

impl<S, N, D> IoLoop<S, N, D>
where
    S: CommitStore + SubstateStore + ConsensusStore + Send + Sync + 'static,
    N: Network,
    D: Dispatch + 'static,
{
    /// Register per-type request handlers with the network.
    ///
    /// Each handler is a closure that captures shared state and delegates to
    /// the serving function in the corresponding protocol module.
    pub(super) fn register_request_handler(&self) {
        use crate::protocol::fetch::{serve_certificate_request, serve_transaction_request};
        use crate::protocol::provision_fetch::serve_provision_request;
        use crate::protocol::sync::serve_block_request;
        use hyperscale_messages::request::{
            GetBlockRequest, GetCertificatesRequest, GetProvisionsRequest, GetTransactionsRequest,
        };

        // ── block.request → sync protocol ────────────────────────────

        let storage = Arc::clone(&self.storage);
        self.network
            .register_request_handler::<GetBlockRequest>(move |req| {
                serve_block_request(&*storage, req)
            });

        // ── transaction.request → fetch protocol ─────────────────────

        let storage = Arc::clone(&self.storage);
        let tx_cache = Arc::clone(&self.tx_cache);
        self.network
            .register_request_handler::<GetTransactionsRequest>(move |req| {
                serve_transaction_request(&*storage, &tx_cache, req)
            });

        // ── certificate.request → fetch protocol ─────────────────────

        let storage = Arc::clone(&self.storage);
        let cert_cache = Arc::clone(&self.cert_cache);
        self.network
            .register_request_handler::<GetCertificatesRequest>(move |req| {
                serve_certificate_request(&*storage, &cert_cache, req)
            });

        // ── provision.request → provision fetch protocol ─────────────

        let storage = Arc::clone(&self.storage);
        let topology = Arc::clone(&self.topology);
        self.network
            .register_request_handler::<GetProvisionsRequest>(move |req| {
                serve_provision_request(&*storage, &*topology, req)
            });
    }

    /// Register gossip handlers for broadcast message types (transactions
    /// and committed block headers).
    pub(super) fn register_gossip_handlers(&self) {
        use hyperscale_network::{GossipVerdict, TopicScope};

        // ── transaction.gossip → ProtocolEvent::TransactionGossipReceived ─
        // The existing step() intercept handles dedup + validation queueing.

        let tx = self.event_sender.clone();
        self.network.register_gossip_handler::<TransactionGossip>(
            TopicScope::Shard,
            move |gossip: TransactionGossip| -> GossipVerdict {
                let _ = tx.send(NodeInput::Protocol(
                    ProtocolEvent::TransactionGossipReceived {
                        tx: gossip.transaction,
                        submitted_locally: false,
                    },
                ));
                GossipVerdict::Accept
            },
        );

        // ── block.committed → pre-filter, then NodeInput::CommittedBlockGossipReceived ─

        let tx = self.event_sender.clone();
        let topology = Arc::clone(&self.topology);
        let local_shard = self.local_shard;
        self.network
            .register_gossip_handler::<hyperscale_messages::CommittedBlockHeaderGossip>(
                TopicScope::Global,
                move |gossip: hyperscale_messages::CommittedBlockHeaderGossip| -> GossipVerdict {
                    let sender = gossip.sender;
                    let header_shard = gossip.committed_header.header.shard_group_id;

                    // Own-shard headers are valid but not needed — accept to forward.
                    if header_shard == local_shard {
                        return GossipVerdict::Accept;
                    }

                    let Some(public_key) =
                        resolve_sender_key(&*topology, sender, header_shard, "committed header")
                    else {
                        return GossipVerdict::Reject;
                    };

                    let _ = tx.send(NodeInput::CommittedBlockGossipReceived {
                        committed_header: gossip.committed_header,
                        sender,
                        public_key,
                        sender_signature: gossip.sender_signature,
                    });
                    GossipVerdict::Accept
                },
            );
    }

    /// Register notification handlers for protocol messages sent via unicast
    /// to known committee members.
    pub(super) fn register_notification_handlers(&self) {
        // ── block.vote → ProtocolEvent::BlockVoteReceived ────────────

        let tx = self.event_sender.clone();
        self.network
            .register_notification_handler::<BlockVoteNotification>(
                move |gossip: BlockVoteNotification| {
                    let _ = tx.send(NodeInput::Protocol(ProtocolEvent::BlockVoteReceived {
                        vote: gossip.vote,
                    }));
                },
            );

        // ── block.header → verify proposer sig, then ProtocolEvent::BlockHeaderReceived ─

        let tx = self.event_sender.clone();
        let topology = Arc::clone(&self.topology);
        self.network
            .register_notification_handler::<BlockHeaderNotification>(
                move |gossip: BlockHeaderNotification| {
                    let proposer = gossip.header.proposer;
                    let Some(public_key) = topology.public_key(proposer) else {
                        warn!(proposer = proposer.0, "Unknown proposer for block header");
                        return;
                    };
                    let msg = gossip.signing_message();
                    if !verify_bls_with_metrics(
                        &msg,
                        &public_key,
                        &gossip.proposer_signature,
                        "block_header",
                    ) {
                        warn!(
                            proposer = proposer.0,
                            height = gossip.header.height.0,
                            round = gossip.header.round,
                            "Block header proposer signature invalid — dropping"
                        );
                        return;
                    }
                    let (header, manifest, _sig) = gossip.into_parts();
                    let _ = tx.send(NodeInput::Protocol(ProtocolEvent::BlockHeaderReceived {
                        header,
                        manifest,
                    }));
                },
            );

        // ── transaction.certificate → verify sender sig, then NodeInput::TransactionCertificateReceived ─

        let tx = self.event_sender.clone();
        let topology = Arc::clone(&self.topology);
        let local_shard = self.local_shard;
        self.network
            .register_notification_handler::<TransactionCertificateNotification>(
                move |gossip: TransactionCertificateNotification| {
                    let sender = gossip.sender;
                    let msg = gossip.signing_message(local_shard);
                    if !verify_sender_signature(
                        &*topology,
                        sender,
                        local_shard,
                        &msg,
                        &gossip.sender_signature,
                        "tx_cert_gossip",
                        "transaction certificate",
                    ) {
                        return;
                    }

                    let _ = tx.send(NodeInput::TransactionCertificateReceived {
                        certificate: gossip.into_certificate(),
                    });
                },
            );

        // ── state.provision.batch → verify sender sig, then ProtocolEvent::StateProvisionsReceived ─

        let tx = self.event_sender.clone();
        let topology = Arc::clone(&self.topology);
        self.network
            .register_notification_handler::<hyperscale_messages::StateProvisionsNotification>(
                move |batch: hyperscale_messages::StateProvisionsNotification| {
                    if batch.provisions.is_empty() {
                        return;
                    }

                    let sender = batch.sender;
                    let source_shard = batch.provisions[0].source_shard;
                    let msg = batch.signing_message();
                    if !verify_sender_signature(
                        &*topology,
                        sender,
                        source_shard,
                        &msg,
                        &batch.sender_signature,
                        "state_provision_batch",
                        "state provision",
                    ) {
                        return;
                    }

                    let provisions = batch.into_provisions();
                    let _ = tx.send(NodeInput::Protocol(
                        ProtocolEvent::StateProvisionsReceived { provisions },
                    ));
                },
            );

        // ── execution.vote.batch → verify sender sig, then ProtocolEvent::ExecutionVoteReceived ─

        let tx = self.event_sender.clone();
        let topology = Arc::clone(&self.topology);
        let local_shard = self.local_shard;
        self.network
            .register_notification_handler::<ExecutionVotesNotification>(
                move |batch: ExecutionVotesNotification| {
                    if batch.votes.is_empty() {
                        return;
                    }

                    let sender = batch.sender;
                    let msg = batch.signing_message(local_shard);
                    if !verify_sender_signature(
                        &*topology,
                        sender,
                        local_shard,
                        &msg,
                        &batch.sender_signature,
                        "exec_vote_batch",
                        "execution vote batch",
                    ) {
                        return;
                    }

                    for vote in batch.into_votes() {
                        let _ =
                            tx.send(NodeInput::Protocol(ProtocolEvent::ExecutionVoteReceived {
                                vote,
                            }));
                    }
                },
            );

        // ── execution.certificate.batch → verify sender sig, then ProtocolEvent::ExecutionCertificateReceived ─

        let tx = self.event_sender.clone();
        let topology = Arc::clone(&self.topology);
        let local_shard = self.local_shard;
        self.network
            .register_notification_handler::<ExecutionCertificatesNotification>(
                move |batch: ExecutionCertificatesNotification| {
                    if batch.certificates.is_empty() {
                        return;
                    }

                    let sender = batch.sender;
                    // The sender is from the shard that produced the certificates,
                    // which may differ from the local shard in cross-shard transactions.
                    let source_shard = batch.certificates[0].shard_group_id;
                    if batch
                        .certificates
                        .iter()
                        .any(|c| c.shard_group_id != source_shard)
                    {
                        warn!(
                            sender = sender.0,
                            "Execution certificate batch contains mixed shard_group_ids — dropping"
                        );
                        return;
                    }
                    let msg = batch.signing_message(local_shard);
                    if !verify_sender_signature(
                        &*topology,
                        sender,
                        source_shard,
                        &msg,
                        &batch.sender_signature,
                        "exec_cert_batch",
                        "execution certificate batch",
                    ) {
                        return;
                    }

                    for cert in batch.into_certificates() {
                        let _ = tx.send(NodeInput::Protocol(
                            ProtocolEvent::ExecutionCertificateReceived { cert },
                        ));
                    }
                },
            );
    }
}
