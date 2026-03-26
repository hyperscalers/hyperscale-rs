//! Network handler registration (gossip, notifications, requests).

use super::verify::{resolve_sender_key, verify_bls_with_metrics, verify_sender_signature};
use super::IoLoop;
use hyperscale_core::{NodeInput, ProtocolEvent};
use hyperscale_dispatch::Dispatch;
use hyperscale_messages::{
    BlockHeaderNotification, BlockVoteNotification, ExecutionWaveCertificatesNotification,
    ExecutionWaveVotesNotification, TransactionGossip,
};
use hyperscale_network::Network;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};
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
        use crate::protocol::fetch::serve_transaction_request;
        use crate::protocol::provision_fetch::serve_provision_request;
        use crate::protocol::sync::serve_block_request;
        use hyperscale_messages::request::{
            GetBlockRequest, GetProvisionsRequest, GetTransactionsRequest,
        };
        use std::sync::Arc;

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

        // ── tx_inclusion_proof.request → livelock proof serving ──────

        let storage = Arc::clone(&self.storage);
        self.network
            .register_request_handler::<hyperscale_messages::request::GetTxInclusionProofRequest>(
                move |req: hyperscale_messages::request::GetTxInclusionProofRequest| {
                    use hyperscale_messages::response::GetTxInclusionProofResponse;
                    use hyperscale_types::tx_inclusion_proof;

                    let (block, _qc) = match storage.get_block(req.block_height) {
                        Some(pair) => pair,
                        None => {
                            return GetTxInclusionProofResponse { proof: None };
                        }
                    };

                    match tx_inclusion_proof(&block, &req.tx_hash) {
                        Some(proof) => GetTxInclusionProofResponse { proof: Some(proof) },
                        None => GetTxInclusionProofResponse { proof: None },
                    }
                },
            );

        // ── provision.request → provision fetch protocol ─────────────
        //
        // Dedup + cache: the proof for (block_height, target_shard) is
        // deterministic. Multiple validators request the same provisions,
        // and retries can send the same request many times. Without dedup,
        // each request regenerates the verkle proof (~30ms), and under load
        // 40+ redundant proof generations per height cause CPU thrashing.
        //
        // The cache stores completed responses. The in-flight map tracks
        // requests currently being computed — subsequent requests for the
        // same key wait on a shared condvar instead of computing again.

        let storage = Arc::clone(&self.storage);
        let topology = self.topology.clone();

        use std::collections::HashMap;

        type ProvisionResponse = hyperscale_messages::response::GetProvisionsResponse;
        type ProvisionWaiter = Arc<(
            std::sync::Mutex<Option<ProvisionResponse>>,
            std::sync::Condvar,
        )>;

        struct ProvisionRequestDedup {
            cache: HashMap<(u64, u64), ProvisionResponse>,
            in_flight: HashMap<(u64, u64), ProvisionWaiter>,
        }

        let dedup: Arc<std::sync::Mutex<ProvisionRequestDedup>> =
            Arc::new(std::sync::Mutex::new(ProvisionRequestDedup {
                cache: HashMap::new(),
                in_flight: HashMap::new(),
            }));

        self.network
            .register_request_handler::<GetProvisionsRequest>(move |req: GetProvisionsRequest| {
                let cache_key = (req.block_height.0, req.target_shard.0);

                // Fast path: check cache
                {
                    let guard = dedup.lock().unwrap();
                    if let Some(cached) = guard.cache.get(&cache_key) {
                        return cached.clone();
                    }
                    // Check if another thread is already computing this
                    if let Some(waiter) = guard.in_flight.get(&cache_key).cloned() {
                        drop(guard); // release lock while waiting
                        let (lock, cvar) = &*waiter;
                        let mut result = lock.lock().unwrap();
                        while result.is_none() {
                            result = cvar.wait(result).unwrap();
                        }
                        return result.clone().unwrap();
                    }
                }

                // We're the first — register as in-flight
                let waiter = Arc::new((
                    std::sync::Mutex::new(
                        None::<hyperscale_messages::response::GetProvisionsResponse>,
                    ),
                    std::sync::Condvar::new(),
                ));
                dedup
                    .lock()
                    .unwrap()
                    .in_flight
                    .insert(cache_key, Arc::clone(&waiter));

                // Compute
                let topo = topology.load();
                let response =
                    serve_provision_request(&*storage, topo.local_shard(), topo.num_shards(), req);

                // Store in cache, notify waiters, remove in-flight
                {
                    let mut guard = dedup.lock().unwrap();
                    if response.provisions.is_some() {
                        guard.cache.insert(cache_key, response.clone());
                        // Evict old entries (keep last 256)
                        if guard.cache.len() > 256 {
                            let min_key = *guard.cache.keys().min().unwrap();
                            guard.cache.remove(&min_key);
                        }
                    }
                    guard.in_flight.remove(&cache_key);
                }

                // Wake all waiters
                let (lock, cvar) = &*waiter;
                *lock.lock().unwrap() = Some(response.clone());
                cvar.notify_all();

                response
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

                    let (provisions, proof) = batch.into_parts();
                    if provisions.is_empty() {
                        return;
                    }
                    let source_shard = provisions[0].source_shard;
                    let block_height = provisions[0].block_height;
                    let transactions: Vec<hyperscale_types::TxEntries> = provisions
                        .into_iter()
                        .map(|p| hyperscale_types::TxEntries {
                            tx_hash: p.transaction_hash,
                            entries: (*p.entries).clone(),
                        })
                        .collect();
                    let batch = hyperscale_types::ProvisionBatch {
                        source_shard,
                        block_height,
                        proof,
                        transactions,
                    };
                    let _ = tx.send(NodeInput::Protocol(
                        ProtocolEvent::StateProvisionsReceived { batch },
                    ));
                },
            );

        // ── execution.wave_vote.batch → verify sender sig, then ProtocolEvent::ExecutionWaveVoteReceived ─

        let tx = self.event_sender.clone();
        let topology = self.topology.clone();
        self.network
            .register_notification_handler::<ExecutionWaveVotesNotification>(
                move |batch: ExecutionWaveVotesNotification| {
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
                        "exec_wave_vote_batch",
                        "execution wave vote batch",
                    ) {
                        return;
                    }

                    for vote in batch.into_votes() {
                        let _ = tx.send(NodeInput::Protocol(
                            ProtocolEvent::ExecutionWaveVoteReceived { vote },
                        ));
                    }
                },
            );

        // ── execution.wave_cert.batch → verify sender sig, then ProtocolEvent::ExecutionWaveCertificateReceived ─

        let tx = self.event_sender.clone();
        let topology = self.topology.clone();
        self.network
            .register_notification_handler::<ExecutionWaveCertificatesNotification>(
                move |batch: ExecutionWaveCertificatesNotification| {
                    if batch.certificates.is_empty() {
                        return;
                    }

                    let topo = topology.load();
                    let sender = batch.sender;
                    let source_shard = batch.certificates[0].shard_group_id;
                    if batch
                        .certificates
                        .iter()
                        .any(|c| c.shard_group_id != source_shard)
                    {
                        warn!(
                            sender = sender.0,
                            "Execution wave certificate batch contains mixed shard_group_ids — dropping"
                        );
                        return;
                    }
                    // Sender signed with source_shard (their local shard), not our local shard
                    let msg = batch.signing_message(source_shard);
                    if !verify_sender_signature(
                        &topo,
                        sender,
                        source_shard,
                        &msg,
                        &batch.sender_signature,
                        "exec_wave_cert_batch",
                        "execution wave certificate batch",
                    ) {
                        return;
                    }

                    for cert in batch.into_certificates() {
                        let _ = tx.send(NodeInput::Protocol(
                            ProtocolEvent::ExecutionWaveCertificateReceived { cert },
                        ));
                    }
                },
            );
    }
}
