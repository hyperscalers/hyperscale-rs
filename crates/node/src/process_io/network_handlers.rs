//! Network handler registration (gossip, notifications, requests).

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::gossip::{CommittedBlockHeaderGossip, TransactionGossip};
use hyperscale_types::network::notification::{
    BlockHeaderNotification, BlockVoteNotification, ExecutionCertificatesNotification,
    ExecutionVotesNotification, ProvisionsNotification, ReadySignalNotification,
};
use hyperscale_types::network::request::beacon::GetShardWitnessesRequest;
use hyperscale_types::network::request::{
    GetExecutionCertsRequest, GetFinalizedWavesRequest, GetLocalProvisionsRequest,
};
use hyperscale_types::network::response::{
    GetLocalProvisionsResponse, GetProvisionResponse, LocalProvisionEntry,
};
use hyperscale_types::{ShardGroupId, ready_signal_message};
use tracing::warn;

use crate::event::ShardScopedInput;
use crate::host::NodeHost;
use crate::shard_io::verify::{
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

        use crate::shard_io::fetch::exec_cert_serve::serve_execution_certs_request;
        use crate::shard_io::fetch::finalized_wave_serve::serve_finalized_waves_request;
        use crate::shard_io::fetch::provision_serve::serve_provision_request;
        use crate::shard_io::fetch::shard_witness_serve::serve_shard_witnesses_request;
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
        // closure captures that shard's `PendingChain` and per-protocol
        // caches. No raw `&S` flows into a serve function: every chain
        // read goes through `PendingChain` so the shard-committed /
        // JMT-persisted window is reachable from one place.
        for shard in self.hosted_shards() {
            // ── block.request → sync protocol ────────────────────────────

            let pending_chain = Arc::clone(&self.shard_io(shard).pending_chain);
            let provision_store = Arc::clone(&self.shard_io(shard).caches.provision_store);
            self.process
                .network
                .register_request_handler::<GetBlockRequest>(shard, move |req| {
                    serve_block_request(&pending_chain, &provision_store, &req)
                });

            // ── transaction.request → fetch protocol ─────────────────────

            let pending_chain = Arc::clone(&self.shard_io(shard).pending_chain);
            let tx_store = Arc::clone(&self.shard_io(shard).caches.tx_store);
            self.process
                .network
                .register_request_handler::<GetTransactionsRequest>(shard, move |req| {
                    serve_transaction_request(&pending_chain, &tx_store, &req)
                });

            // ── provision.request → serve from local store ───────────────
            //
            // Dedup + cache: the proof for (block_height, target_shard) is
            // deterministic, and many validators request the same provisions.
            // Without dedup each request regenerates the merkle proof (~30ms),
            // and under load 40+ redundant generations per height cause CPU
            // thrashing.

            let pending_chain = Arc::clone(&self.shard_io(shard).pending_chain);
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

                        let response =
                            serve_provision_request(&pending_chain, shard, num_shards, &req);
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
            let verified_headers = Arc::clone(&self.shard_io(shard).caches.verified_headers);
            self.process
                .network
                .register_request_handler::<GetLocalProvisionsRequest>(
                    shard,
                    move |req: GetLocalProvisionsRequest| {
                        // Bundle the matching source header alongside each
                        // returned blob so the requester can verify and admit
                        // without first racing the remote-header pipeline.
                        // Both lookups read the same maps the coordinator
                        // writes through, so a present blob implies the
                        // header was admitted at some point; `None` means
                        // it's since been GC'd (retention sweep) and the
                        // requester falls back to the buffered path.
                        let mut entries = Vec::with_capacity(req.batch_hashes.len());
                        for h in &req.batch_hashes {
                            if let Some(provisions) = provision_store.get(*h) {
                                let source_header = verified_headers
                                    .get((provisions.source_shard(), provisions.block_height()));
                                entries.push(LocalProvisionEntry {
                                    provisions,
                                    source_header,
                                });
                            }
                        }

                        GetLocalProvisionsResponse::new(entries)
                    },
                );

            // ── finalized_wave.request → cache lookup + pending_chain fallback ─

            let fw_cache = Arc::clone(&self.shard_io(shard).caches.finalized_wave);
            let pending_chain = Arc::clone(&self.shard_io(shard).pending_chain);
            self.process
                .network
                .register_request_handler::<GetFinalizedWavesRequest>(shard, move |req| {
                    serve_finalized_waves_request(&pending_chain, &fw_cache, &req)
                });

            // ── execution_cert.request → cert store lookup ────────────────

            let exec_cert_store = Arc::clone(&self.shard_io(shard).caches.exec_cert_store);
            let pending_chain = Arc::clone(&self.shard_io(shard).pending_chain);
            self.process
                .network
                .register_request_handler::<GetExecutionCertsRequest>(shard, move |req| {
                    serve_execution_certs_request(&pending_chain, &exec_cert_store, &req)
                });

            // ── remote_header.request → range header sync ───────────────────

            let pending_chain = Arc::clone(&self.shard_io(shard).pending_chain);
            self.process
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

            let pending_chain = Arc::clone(&self.shard_io(shard).pending_chain);
            self.process
                .network
                .register_request_handler::<GetShardWitnessesRequest>(shard, move |req| {
                    serve_shard_witnesses_request(&pending_chain, &req)
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

        let senders = self.process.shard_event_senders.clone();
        self.process
            .network
            .register_gossip_handler::<TransactionGossip>(
                move |gossip: TransactionGossip, shard: ShardGroupId| -> GossipVerdict {
                    let Some(tx) = senders.get(&shard) else {
                        warn!(
                            shard = shard.inner(),
                            "Dropping tx gossip: shard not hosted"
                        );
                        return GossipVerdict::Reject;
                    };
                    for transaction in gossip.transactions.into_inner() {
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
            .register_gossip_handler::<CommittedBlockHeaderGossip>(
                move |gossip: CommittedBlockHeaderGossip,
                      target_shard: ShardGroupId|
                      -> GossipVerdict {
                    let Some(tx) = senders.get(&target_shard) else {
                        warn!(
                            target_shard = target_shard.inner(),
                            "Dropping committed header gossip: shard not hosted"
                        );
                        return GossipVerdict::Reject;
                    };
                    let sender = gossip.sender;
                    let header_shard = gossip.committed_header.header().shard_group_id();
                    let topo = topology.load();

                    let Some(public_key) =
                        resolve_sender_key(&topo, sender, header_shard, "committed header")
                    else {
                        return GossipVerdict::Reject;
                    };

                    push_shard_input(
                        tx,
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
        // ── block.vote → ProtocolEvent::BlockVoteReceived ────────────
        //
        // `BlockVote.shard_group_id()` is the shard whose consensus the
        // vote is for; with cross-shard hosting that selects which of
        // this host's vnodes the event fans out to. Drop early if the
        // vote targets a shard we don't host.

        let senders = self.process.shard_event_senders.clone();
        self.process
            .network
            .register_notification_handler::<BlockVoteNotification>(
                move |gossip: BlockVoteNotification| {
                    let shard = gossip.vote.shard_group_id();
                    let Some(tx) = senders.get(&shard) else {
                        warn!(
                            target_shard = shard.inner(),
                            "Dropping block vote: shard not hosted"
                        );
                        return;
                    };
                    push_protocol_event(
                        tx,
                        shard,
                        ProtocolEvent::BlockVoteReceived { vote: gossip.vote },
                    );
                },
            );

        // ── block.header → verify proposer sig, then ProtocolEvent::BlockHeaderReceived ─

        let senders = self.process.shard_event_senders.clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_notification_handler::<BlockHeaderNotification>(
                move |gossip: BlockHeaderNotification| {
                    let shard = gossip.header.shard_group_id();
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

        // ── provisions.broadcast → verify sender sig, then ProtocolEvent::ProvisionsReceived ─

        let senders = self.process.shard_event_senders.clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .network
            .register_notification_handler::<ProvisionsNotification>(
                move |notification: ProvisionsNotification| {
                    let target_shard = notification.provisions.target_shard();
                    // Drop provisions not destined for any hosted shard before
                    // paying the BLS verification cost.
                    let Some(tx) = senders.get(&target_shard) else {
                        warn!(
                            source_shard = notification.provisions.source_shard().inner(),
                            target_shard = target_shard.inner(),
                            "Dropping provisions notification: target_shard not hosted"
                        );
                        return;
                    };

                    let topo = topology.load();
                    let source_shard = notification.provisions.source_shard();
                    if !verify_signed_by_committee(
                        &topo,
                        source_shard,
                        &notification,
                        "state_provisions",
                        "state provision",
                    ) {
                        return;
                    }

                    push_protocol_event(
                        tx,
                        target_shard,
                        ProtocolEvent::ProvisionsReceived {
                            provisions: notification.provisions,
                        },
                    );
                },
            );

        // ── execution.vote.batch → verify sender sig, then ProtocolEvent::ExecutionVoteReceived ─

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
                    let target_shard = batch.votes[0].shard_group_id();
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

                    for vote in batch.into_votes() {
                        push_protocol_event(
                            tx,
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

                    let certificates = batch.into_certificates();
                    // Fan out across every hosted shard — the destination
                    // shard for a cert isn't known here without inspecting
                    // expected-cert sets, so each hosted shard decides
                    // whether to admit (no-op if unexpected).
                    for (hosted_shard, tx) in &senders {
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
                        signal.height_window_start(),
                        signal.height_window_end(),
                    );
                    if !verify_bls_with_metrics(&msg, &public_key, &signal.sig(), "ready_signal") {
                        warn!(
                            sender = sender.inner(),
                            "Ready signal BLS verify failed — dropping"
                        );
                        return;
                    }
                    for (hosted_shard, tx) in &senders {
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
    }
}
