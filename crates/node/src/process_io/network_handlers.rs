//! Network handler registration (gossip, notifications, requests).

use std::collections::HashSet;

use hyperscale_core::ProtocolEvent;
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
use hyperscale_types::{ExecutionCertificate, FinalizedWave, ShardGroupId, WaveId};
use tracing::warn;

use crate::event::ShardScopedInput;
use crate::host::NodeHost;
use crate::shard_io::verify::{
    resolve_sender_key, verify_bls_with_metrics, verify_sender_signature,
};
use crate::shard_loop::{push_protocol_event, push_shard_input};

impl<S, N, D, E> NodeHost<S, N, D, E>
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
    pub(crate) fn register_request_handler(&self) {
        use std::collections::HashMap;
        use std::sync::Arc;

        use hyperscale_types::network::request::{
            GetBlockRequest, GetProvisionsRequest, GetRemoteHeadersRequest, GetTransactionsRequest,
        };

        use crate::shard_io::fetch::provision_serve::serve_provision_request;
        use crate::shard_io::fetch::transaction_serve::serve_transaction_request;
        use crate::shard_io::sync::block_serve::serve_block_request;
        use crate::shard_io::sync::remote_header_serve::serve_remote_headers_request;

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

        // One set of request handlers per hosted shard — each handler
        // closure captures that shard's storage and caches.
        for shard in self.hosted_shards() {
            // ── block.request → sync protocol ────────────────────────────

            let storage = Arc::clone(&self.shard_io(shard).storage);
            let provision_store = Arc::clone(&self.shard_io(shard).caches.provision_store);
            self.process
                .network
                .register_request_handler::<GetBlockRequest>(shard, move |req| {
                    serve_block_request(&*storage, &provision_store, &req)
                });

            // ── transaction.request → fetch protocol ─────────────────────

            let storage = Arc::clone(&self.shard_io(shard).storage);
            let tx_store = Arc::clone(&self.shard_io(shard).caches.tx_store);
            self.process
                .network
                .register_request_handler::<GetTransactionsRequest>(shard, move |req| {
                    serve_transaction_request(&*storage, &tx_store, &req)
                });

            // ── provision.request → serve from local store ───────────────
            //
            // Dedup + cache: the proof for (block_height, target_shard) is
            // deterministic, and many validators request the same provisions.
            // Without dedup each request regenerates the merkle proof (~30ms),
            // and under load 40+ redundant generations per height cause CPU
            // thrashing.

            let storage = Arc::clone(&self.shard_io(shard).storage);
            let num_shards = self.process.topology_snapshot.load().num_shards();
            let outbound_cache = Arc::clone(&self.shard_io(shard).caches.provision_store);

            let dedup: Arc<std::sync::Mutex<ProvisionsRequestDedup>> =
                Arc::new(std::sync::Mutex::new(ProvisionsRequestDedup {
                    cache: std::collections::BTreeMap::new(),
                    in_flight: HashMap::new(),
                }));

            self.process
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
                            record_fetch_response_sent(
                                "provision",
                                provisions.transactions().len().max(1),
                            );
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
                                    record_fetch_response_sent(
                                        "provision",
                                        p.transactions().len().max(1),
                                    );
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
                            let wait_result = cvar.wait_timeout_while(
                                lock.lock().unwrap(),
                                PRODUCER_WAIT_BUDGET,
                                |r| r.is_none(),
                            );
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

                        let response = serve_provision_request(&*storage, shard, num_shards, &req);
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
                    },
                );

            // ── local_provision.request → provision cache lookup ─────────

            let provision_store = Arc::clone(&self.shard_io(shard).caches.provision_store);
            self.process
                .network
                .register_request_handler::<GetLocalProvisionsRequest>(
                    shard,
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

            let fw_cache = Arc::clone(&self.shard_io(shard).caches.finalized_wave);
            let fw_storage = Arc::clone(&self.shard_io(shard).storage);
            self.process
                .network
                .register_request_handler::<GetFinalizedWavesRequest>(
                    shard,
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

            let exec_cert_store = Arc::clone(&self.shard_io(shard).caches.exec_cert_store);
            let storage = Arc::clone(&self.shard_io(shard).storage);
            self.process
                .network
                .register_request_handler::<GetExecutionCertsRequest>(
                    shard,
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

            let storage = Arc::clone(&self.shard_io(shard).storage);
            self.process
                .network
                .register_request_handler::<GetRemoteHeadersRequest>(shard, move |req| {
                    serve_remote_headers_request(&*storage, shard, &req)
                });
        } // end for shard in hosted_shards
    }

    /// Register gossip handlers for broadcast message types (transactions
    /// and committed block headers).
    ///
    /// Both handler closures see a single `(message, target_shard)` pair —
    /// the network framework computes the per-vnode fan-out from each
    /// type's [`GossipMessage::SCOPE`] and [`GossipMessage::source_shard`].
    /// Closures here just translate into `ShardScopedInput`.
    pub(crate) fn register_gossip_handlers(&self) {
        use hyperscale_network::GossipVerdict;

        // ── transaction.gossip → ShardScopedInput::TransactionGossipReceived ─

        let tx = self.process.event_sender.clone();
        self.process
            .network
            .register_gossip_handler::<TransactionGossip>(
                move |gossip: TransactionGossip, shard: ShardGroupId| -> GossipVerdict {
                    for transaction in gossip.transactions.into_inner() {
                        push_shard_input(
                            &tx,
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

        let tx = self.process.event_sender.clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_gossip_handler::<CommittedBlockHeaderGossip>(
                move |gossip: CommittedBlockHeaderGossip,
                      target_shard: ShardGroupId|
                      -> GossipVerdict {
                    let sender = gossip.sender;
                    let header_shard = gossip.committed_header.header().shard_group_id();
                    let topo = topology.load();

                    let Some(public_key) =
                        resolve_sender_key(&topo, sender, header_shard, "committed header")
                    else {
                        return GossipVerdict::Reject;
                    };

                    push_shard_input(
                        &tx,
                        target_shard,
                        ShardScopedInput::CommittedBlockGossipReceived {
                            committed_header: gossip.committed_header,
                            sender,
                            public_key,
                            sender_signature: gossip.sender_signature,
                        },
                    );
                    GossipVerdict::Accept
                },
            );
    }

    /// Register notification handlers for protocol messages sent via unicast
    /// to known committee members.
    #[allow(clippy::too_many_lines)] // single registration table; one closure per notification type
    pub(crate) fn register_notification_handlers(&self) {
        // Hosted-shard set snapshotted at registration.
        let hosted_shards: std::sync::Arc<HashSet<ShardGroupId>> =
            std::sync::Arc::new(self.hosted_shards().collect());

        // ── block.vote → ProtocolEvent::BlockVoteReceived ────────────
        //
        // `BlockVote.shard_group_id()` is the shard whose consensus the
        // vote is for; with cross-shard hosting that selects which of
        // this host's vnodes the event fans out to. Drop early if the
        // vote targets a shard we don't host.

        let tx = self.process.event_sender.clone();
        let shards = std::sync::Arc::clone(&hosted_shards);
        self.process
            .network
            .register_notification_handler::<BlockVoteNotification>(
                move |gossip: BlockVoteNotification| {
                    let shard = gossip.vote.shard_group_id();
                    if !shards.contains(&shard) {
                        warn!(
                            target_shard = shard.inner(),
                            "Dropping block vote: shard not hosted"
                        );
                        return;
                    }
                    push_protocol_event(
                        &tx,
                        shard,
                        ProtocolEvent::BlockVoteReceived { vote: gossip.vote },
                    );
                },
            );

        // ── block.header → verify proposer sig, then ProtocolEvent::BlockHeaderReceived ─

        let tx = self.process.event_sender.clone();
        let topology = self.process.topology_snapshot.clone();
        let shards = std::sync::Arc::clone(&hosted_shards);
        self.process
            .network
            .register_notification_handler::<BlockHeaderNotification>(
                move |gossip: BlockHeaderNotification| {
                    let shard = gossip.header.shard_group_id();
                    if !shards.contains(&shard) {
                        warn!(
                            target_shard = shard.inner(),
                            "Dropping block header: shard not hosted"
                        );
                        return;
                    }
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
                    push_protocol_event(
                        &tx,
                        shard,
                        ProtocolEvent::BlockHeaderReceived { header, manifest },
                    );
                },
            );

        // ── provisions.broadcast → verify sender sig, then ProtocolEvent::ProvisionsReceived ─

        let tx = self.process.event_sender.clone();
        let topology = self.process.topology_snapshot.clone();
        let shards = std::sync::Arc::clone(&hosted_shards);
        self.process
            .network
            .register_notification_handler::<ProvisionsNotification>(
                move |notification: ProvisionsNotification| {
                    let target_shard = notification.provisions.target_shard();
                    // Drop provisions not destined for any hosted shard before
                    // paying the BLS verification cost.
                    if !shards.contains(&target_shard) {
                        warn!(
                            source_shard = notification.provisions.source_shard().inner(),
                            target_shard = target_shard.inner(),
                            "Dropping provisions notification: target_shard not hosted"
                        );
                        return;
                    }

                    let topo = topology.load();
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

                    push_protocol_event(
                        &tx,
                        target_shard,
                        ProtocolEvent::ProvisionsReceived {
                            provisions: notification.provisions,
                        },
                    );
                },
            );

        // ── execution.vote.batch → verify sender sig, then ProtocolEvent::ExecutionVoteReceived ─

        let tx = self.process.event_sender.clone();
        let topology = self.process.topology_snapshot.clone();
        let shards = std::sync::Arc::clone(&hosted_shards);
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
                    let target_shard = batch.votes[0].shard_group_id();
                    if !shards.contains(&target_shard) {
                        warn!(
                            target_shard = target_shard.inner(),
                            "Dropping execution vote batch: shard not hosted"
                        );
                        return;
                    }

                    let topo = topology.load();
                    let sender = batch.sender;
                    let msg = batch.signing_message(target_shard);
                    if !verify_sender_signature(
                        &topo,
                        sender,
                        target_shard,
                        &msg,
                        &batch.sender_signature,
                        "exec_vote_batch",
                        "execution vote batch",
                    ) {
                        return;
                    }

                    for vote in batch.into_votes() {
                        push_protocol_event(
                            &tx,
                            target_shard,
                            ProtocolEvent::ExecutionVoteReceived { vote },
                        );
                    }
                },
            );

        // ── execution.cert.batch → verify sender sig, then ProtocolEvent::ExecutionCertificatesReceived ─
        //
        // The cert's `shard_group_id` is the *source* shard (sender's
        // shard). With cross-shard hosting we may consume an EC for any
        // of our hosted shards as the destination, so the relevant
        // "target hosted shard" is determined later by the state machine.
        // For routing purposes we forward to every hosted shard so
        // each receiving coordinator can decide whether the cert is for it.

        let tx = self.process.event_sender.clone();
        let topology = self.process.topology_snapshot.clone();
        let shards = std::sync::Arc::clone(&hosted_shards);
        self.process
            .network
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

                    let certificates = batch.into_certificates();
                    // Fan out across every hosted shard — the destination
                    // shard for a cert isn't known here without inspecting
                    // expected-cert sets, so each hosted shard decides
                    // whether to admit (no-op if unexpected).
                    for hosted_shard in shards.iter() {
                        push_protocol_event(
                            &tx,
                            *hosted_shard,
                            ProtocolEvent::ExecutionCertificatesReceived {
                                certificates: certificates.clone(),
                            },
                        );
                    }
                },
            );
    }
}
