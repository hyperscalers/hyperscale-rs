//! Network handler registration (gossip, notifications, requests).

use super::verify::{resolve_sender_key, verify_bls_with_metrics, verify_sender_signature};
use super::IoLoop;
use hyperscale_core::{NodeConfig, NodeInput, ProtocolEvent};
use hyperscale_messages::{
    BlockHeaderNotification, BlockVoteNotification, ExecutionCertificatesNotification,
    ExecutionVotesNotification, TransactionGossip,
};
use hyperscale_radix_config::RadixConfig;
use tracing::warn;

impl<Cfg: NodeConfig<C = RadixConfig>> IoLoop<Cfg> {
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
        use hyperscale_network::Network;
        use std::sync::Arc;

        // ── block.request → sync protocol ────────────────────────────

        let storage = Arc::clone(&self.storage);
        self.network
            .register_request_handler::<GetBlockRequest>(move |req| {
                serve_block_request::<Cfg::C>(&*storage, req)
            });

        // ── transaction.request → fetch protocol ─────────────────────

        let storage = Arc::clone(&self.storage);
        let tx_cache = Arc::clone(&self.tx_cache);
        self.network
            .register_request_handler::<GetTransactionsRequest>(move |req| {
                serve_transaction_request::<Cfg::C>(&*storage, &tx_cache, req)
            });

        // ── certificate.request → fetch protocol ─────────────────────

        let storage = Arc::clone(&self.storage);
        let cert_cache = Arc::clone(&self.cert_cache);
        self.network
            .register_request_handler::<GetCertificatesRequest>(move |req| {
                serve_certificate_request::<Cfg::C>(&*storage, &cert_cache, req)
            });

        // ── provision.request → provision fetch protocol ─────────────

        let storage = Arc::clone(&self.storage);
        let topology = self.topology.clone();
        self.network
            .register_request_handler::<GetProvisionsRequest>(move |req| {
                let topo = topology.load();
                serve_provision_request::<Cfg::C>(
                    &*storage,
                    topo.local_shard(),
                    topo.num_shards(),
                    req,
                )
            });
    }

    /// Register gossip handlers for broadcast message types (transactions
    /// and committed block headers).
    pub(super) fn register_gossip_handlers(&self) {
        use hyperscale_network::{GossipVerdict, Network, TopicScope};

        // ── transaction.gossip → ProtocolEvent::TransactionGossipReceived ─
        // The existing step() intercept handles dedup + validation queueing.

        let tx = self.event_sender.clone();
        self.network
            .register_gossip_handler::<TransactionGossip<Cfg::C>>(
                TopicScope::Shard,
                move |gossip: TransactionGossip<Cfg::C>| -> GossipVerdict {
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
        let topology = self.topology.clone();
        self.network
            .register_gossip_handler::<hyperscale_messages::CommittedBlockHeaderGossip>(
                TopicScope::Global,
                move |gossip: hyperscale_messages::CommittedBlockHeaderGossip| -> GossipVerdict {
                    let sender = gossip.sender;
                    let header_shard = gossip.committed_header.header.shard_group_id;
                    let topo = topology.load();

                    // Own-shard headers are valid but not needed — accept to forward.
                    if header_shard == topo.local_shard() {
                        return GossipVerdict::Accept;
                    }

                    let Some(public_key) =
                        resolve_sender_key(&topo, sender, header_shard, "committed header")
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
        use hyperscale_network::Network;

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
        let topology = self.topology.clone();
        self.network
            .register_notification_handler::<BlockHeaderNotification>(
                move |gossip: BlockHeaderNotification| {
                    let topo = topology.load();
                    let proposer = gossip.header.proposer;
                    let Some(public_key) = topo.public_key(proposer) else {
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

        // ── state.provision.batch → verify sender sig, then ProtocolEvent::StateProvisionsReceived ─

        let tx = self.event_sender.clone();
        let topology = self.topology.clone();
        self.network
            .register_notification_handler::<hyperscale_messages::StateProvisionsNotification>(
                move |batch: hyperscale_messages::StateProvisionsNotification| {
                    if batch.provisions.is_empty() {
                        return;
                    }

                    let topo = topology.load();
                    let sender = batch.sender;
                    let source_shard = batch.provisions[0].source_shard;
                    let msg = batch.signing_message();
                    if !verify_sender_signature(
                        &topo,
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
        let topology = self.topology.clone();
        self.network
            .register_notification_handler::<ExecutionVotesNotification>(
                move |batch: ExecutionVotesNotification| {
                    if batch.votes.is_empty() {
                        return;
                    }

                    let topo = topology.load();
                    let local_shard = topo.local_shard();
                    let sender = batch.sender;
                    let msg = batch.signing_message(local_shard);
                    if !verify_sender_signature(
                        &topo,
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
        let topology = self.topology.clone();
        self.network
            .register_notification_handler::<ExecutionCertificatesNotification>(
                move |batch: ExecutionCertificatesNotification| {
                    if batch.certificates.is_empty() {
                        return;
                    }

                    let topo = topology.load();
                    let local_shard = topo.local_shard();
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
                        &topo,
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
