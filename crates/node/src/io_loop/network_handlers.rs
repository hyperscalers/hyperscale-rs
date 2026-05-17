//! Network handler registration (gossip, notifications, requests).

use hyperscale_core::{NodeInput, ProtocolEvent};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::network::gossip::{CommittedBlockHeaderGossip, TransactionGossip};
use hyperscale_types::network::notification::{
    BlockHeaderNotification, BlockVoteNotification, ExecutionCertificatesNotification,
    ExecutionVotesNotification, ProvisionsNotification,
};
use hyperscale_types::network::request::{
    GetExecutionCertsRequest, GetFinalizedWavesRequest, GetLocalProvisionsRequest,
};
use hyperscale_types::network::response::{
    GetExecutionCertsResponse, GetFinalizedWavesResponse, GetLocalProvisionsResponse,
    GetProvisionResponse,
};
use hyperscale_types::{ExecutionCertificate, FinalizedWave, WaveId};
use tracing::warn;

use super::IoLoop;
use crate::shard::verify::{resolve_sender_key, verify_bls_with_metrics, verify_sender_signature};

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Register per-type request handlers with the network.
    ///
    /// Each handler is a closure that captures shared state and delegates to
    /// the serving function in the corresponding protocol module.
    #[allow(clippy::too_many_lines)] // single registration table; one closure per request type
    pub(super) fn register_request_handler(&self) {
        use std::collections::HashMap;
        use std::sync::Arc;

        use hyperscale_types::network::request::{
            GetBlockRequest, GetProvisionsRequest, GetRemoteHeadersRequest, GetTransactionsRequest,
        };

        use crate::shard::fetch::provision_serve::serve_provision_request;
        use crate::shard::fetch::transaction_serve::serve_transaction_request;
        use crate::shard::sync::block_serve::serve_block_request;
        use crate::shard::sync::remote_header_serve::serve_remote_headers_request;

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

        // ── block.request → sync protocol ────────────────────────────

        let storage = Arc::clone(self.shard_storage());
        let provision_store = Arc::clone(&self.shard_caches().provision_store);
        self.network
            .register_request_handler::<GetBlockRequest>(move |req| {
                serve_block_request(&*storage, &provision_store, &req)
            });

        // ── transaction.request → fetch protocol ─────────────────────

        let storage = Arc::clone(self.shard_storage());
        let tx_store = Arc::clone(&self.shard_caches().tx_store);
        self.network
            .register_request_handler::<GetTransactionsRequest>(move |req| {
                serve_transaction_request(&*storage, &tx_store, &req)
            });

        // ── provision.request → serve from local store ───────────────
        //
        // Dedup + cache: the proof for (block_height, target_shard) is
        // deterministic, and many validators request the same provisions.
        // Without dedup each request regenerates the merkle proof (~30ms),
        // and under load 40+ redundant generations per height cause CPU
        // thrashing.

        let storage = Arc::clone(self.shard_storage());
        let topology = self.topology_snapshot.clone();
        let outbound_cache = Arc::clone(&self.shard_caches().provision_store);

        let dedup: Arc<std::sync::Mutex<ProvisionsRequestDedup>> =
            Arc::new(std::sync::Mutex::new(ProvisionsRequestDedup {
                cache: std::collections::BTreeMap::new(),
                in_flight: HashMap::new(),
            }));

        self.network
            .register_request_handler::<GetProvisionsRequest>(move |req: GetProvisionsRequest| {
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

                let topo = topology.load();
                let response =
                    serve_provision_request(&*storage, topo.local_shard(), topo.num_shards(), &req);
                if let Some(p) = &response.provisions {
                    record_fetch_response_sent("provision", p.transactions().len());
                }

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
            });

        // ── local_provision.request → provision cache lookup ─────────

        let provision_store = Arc::clone(&self.shard_caches().provision_store);
        self.network
            .register_request_handler::<GetLocalProvisionsRequest>(
                move |req: GetLocalProvisionsRequest| {
                    let mut provisions = Vec::with_capacity(req.batch_hashes.len());
                    for h in &req.batch_hashes {
                        if let Some(b) = provision_store.get(*h) {
                            provisions.push(b);
                        }
                    }

                    GetLocalProvisionsResponse::new(provisions)
                },
            );

        // ── finalized_wave.request → cache lookup + storage fallback ─────

        let fw_cache = Arc::clone(&self.shard_caches().finalized_wave);
        let fw_storage = Arc::clone(self.shard_storage());
        self.network
            .register_request_handler::<GetFinalizedWavesRequest>(
                move |req: GetFinalizedWavesRequest| {
                    let mut waves: Vec<Arc<FinalizedWave>> = Vec::new();
                    let mut missing: Vec<WaveId> = Vec::new();
                    for id in &req.wave_ids {
                        if let Some(fw) = fw_cache.get(id) {
                            waves.push(fw);
                        } else {
                            missing.push(id.clone());
                        }
                    }

                    // Storage fallback: rebuild any missing FinalizedWave
                    // from the persisted WaveCertificate plus per-tx
                    // consensus receipts. The cache is bounded (LRU); peers
                    // requesting waves past the window must still get a
                    // complete answer from durable storage.
                    if !missing.is_empty() {
                        let certs = fw_storage.get_certificates_batch(&missing);
                        for cert in certs {
                            if let Some(fw) = FinalizedWave::reconstruct(Arc::new(cert), |h| {
                                fw_storage.get_consensus_receipt(h)
                            }) {
                                waves.push(Arc::new(fw));
                            }
                        }
                    }

                    GetFinalizedWavesResponse::new(waves)
                },
            );

        // ── execution_cert.request → cert store lookup ────────────────

        let exec_cert_store = Arc::clone(&self.shard_caches().exec_cert_store);
        let storage = Arc::clone(self.shard_storage());
        self.network
            .register_request_handler::<GetExecutionCertsRequest>(
                move |req: GetExecutionCertsRequest| {
                    // Hot path: in-memory cache (entries live here between EC
                    // aggregation and the wave's containing block committing).
                    let mut certs: Vec<Arc<ExecutionCertificate>> = Vec::new();
                    let mut missing: Vec<WaveId> = Vec::new();
                    for wave_id in &req.wave_ids {
                        match exec_cert_store.get(wave_id) {
                            Some(cert) => certs.push(cert),
                            None => missing.push(wave_id.clone()),
                        }
                    }

                    // Cold path: durable storage point lookup per missing
                    // wave_id. Cache eviction happens at wave-cert commit, at
                    // which point storage is the authoritative source.
                    if !missing.is_empty() {
                        for cert in storage.get_execution_certificates_batch(&missing) {
                            certs.push(Arc::new(cert));
                        }
                    }

                    if certs.is_empty() {
                        GetExecutionCertsResponse { certificates: None }
                    } else {
                        record_fetch_response_sent("exec_cert", certs.len());
                        GetExecutionCertsResponse {
                            certificates: Some(certs),
                        }
                    }
                },
            );

        // ── remote_header.request → range header sync ───────────────────

        let storage = Arc::clone(self.shard_storage());
        let topology = self.topology_snapshot.clone();
        self.network
            .register_request_handler::<GetRemoteHeadersRequest>(move |req| {
                let local_shard = topology.load().local_shard();
                serve_remote_headers_request(&*storage, local_shard, &req)
            });
    }

    /// Register gossip handlers for broadcast message types (transactions
    /// and committed block headers).
    pub(super) fn register_gossip_handlers(&self) {
        use hyperscale_network::{GossipVerdict, TopicScope};

        // ── transaction.gossip → NodeInput::TransactionGossipReceived ─
        // The step() handler dedups against tx_store / tombstones and
        // enqueues for batched async validation.

        let tx = self.event_sender.clone();
        self.network.register_gossip_handler::<TransactionGossip>(
            TopicScope::Shard,
            move |gossip: TransactionGossip| -> GossipVerdict {
                for transaction in gossip.transactions {
                    let _ = tx.send(NodeInput::TransactionGossipReceived { tx: transaction });
                }
                GossipVerdict::Accept
            },
        );

        // ── block.committed → pre-filter, then NodeInput::CommittedBlockGossipReceived ─

        let tx = self.event_sender.clone();
        let topology = self.topology_snapshot.clone();
        self.network
            .register_gossip_handler::<CommittedBlockHeaderGossip>(
                TopicScope::Global,
                move |gossip: CommittedBlockHeaderGossip| -> GossipVerdict {
                    let sender = gossip.sender;
                    let header_shard = gossip.committed_header.header().shard_group_id();
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
                        committed_header: Box::new(gossip.committed_header),
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
    #[allow(clippy::too_many_lines)] // single registration table; one closure per notification type
    pub(super) fn register_notification_handlers(&self) {
        // ── block.vote → ProtocolEvent::BlockVoteReceived ────────────

        let tx = self.event_sender.clone();
        self.network
            .register_notification_handler::<BlockVoteNotification>(
                move |gossip: BlockVoteNotification| {
                    let _ = tx.send(NodeInput::Protocol(Box::new(
                        ProtocolEvent::BlockVoteReceived { vote: gossip.vote },
                    )));
                },
            );

        // ── block.header → verify proposer sig, then ProtocolEvent::BlockHeaderReceived ─

        let tx = self.event_sender.clone();
        let topology = self.topology_snapshot.clone();
        self.network
            .register_notification_handler::<BlockHeaderNotification>(
                move |gossip: BlockHeaderNotification| {
                    let topo = topology.load();
                    let proposer = gossip.header.proposer();
                    let Some(public_key) = topo.public_key(proposer) else {
                        warn!(
                            proposer = proposer.inner(),
                            "Unknown proposer for block header"
                        );
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
                            proposer = proposer.inner(),
                            height = gossip.header.height().inner(),
                            round = gossip.header.round().inner(),
                            "Block header proposer signature invalid — dropping"
                        );
                        return;
                    }
                    let (header, manifest, _sig) = gossip.into_parts();
                    let _ = tx.send(NodeInput::Protocol(Box::new(
                        ProtocolEvent::BlockHeaderReceived { header, manifest },
                    )));
                },
            );

        // ── provisions.broadcast → verify sender sig, then ProtocolEvent::ProvisionsReceived ─

        let tx = self.event_sender.clone();
        let topology = self.topology_snapshot.clone();
        self.network
            .register_notification_handler::<ProvisionsNotification>(
                move |notification: ProvisionsNotification| {
                    let topo = topology.load();

                    // Drop provisions not destined for our shard before paying
                    // the BLS verification cost. Catches misroutes and spam early.
                    if notification.provisions.target_shard() != topo.local_shard() {
                        warn!(
                            source_shard = notification.provisions.source_shard().inner(),
                            target_shard = notification.provisions.target_shard().inner(),
                            local_shard = topo.local_shard().inner(),
                            "Dropping provisions notification: target_shard mismatch"
                        );
                        return;
                    }

                    let sender = notification.sender;
                    let source_shard = notification.provisions.source_shard();
                    let msg = notification.signing_message();
                    if !verify_sender_signature(
                        &topo,
                        sender,
                        source_shard,
                        &msg,
                        &notification.sender_signature,
                        "state_provisions",
                        "state provision",
                    ) {
                        return;
                    }

                    let _ = tx.send(NodeInput::Protocol(Box::new(
                        ProtocolEvent::ProvisionsReceived {
                            provisions: notification.provisions,
                        },
                    )));
                },
            );

        // ── execution.vote.batch → verify sender sig, then ProtocolEvent::ExecutionVoteReceived ─

        let tx = self.event_sender.clone();
        let topology = self.topology_snapshot.clone();
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
                        let _ = tx.send(NodeInput::Protocol(Box::new(
                            ProtocolEvent::ExecutionVoteReceived { vote },
                        )));
                    }
                },
            );

        // ── execution.cert.batch → verify sender sig, then ProtocolEvent::ExecutionCertificatesReceived ─

        let tx = self.event_sender.clone();
        let topology = self.topology_snapshot.clone();
        self.network
            .register_notification_handler::<ExecutionCertificatesNotification>(
                move |batch: ExecutionCertificatesNotification| {
                    if batch.certificates.is_empty() {
                        return;
                    }

                    let topo = topology.load();
                    let sender = batch.sender;
                    let source_shard = batch.certificates[0].shard_group_id();
                    if batch
                        .certificates
                        .iter()
                        .any(|c| c.shard_group_id() != source_shard)
                    {
                        warn!(
                            sender = sender.inner(),
                            "Execution certificate batch contains mixed shard_group_ids — dropping"
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
                        "exec_cert_batch",
                        "execution certificate batch",
                    ) {
                        return;
                    }

                    let _ = tx.send(NodeInput::Protocol(Box::new(
                        ProtocolEvent::ExecutionCertificatesReceived {
                            certificates: batch.into_certificates(),
                        },
                    )));
                },
            );
    }
}
