//! Production network adapter implementing the Network trait.
//!
//! [`Libp2pNetwork`] wraps [`Libp2pAdapter`] and [`RequestManager`] to provide
//! the [`Network`] interface used by `IoLoop` in the production runner.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use hyperscale_metrics::record_request_retry;
use hyperscale_network::compression::compress;
use hyperscale_network::fault::Tier;
use hyperscale_network::{
    GossipHandler, GossipVerdict, HandlerRegistry, Network, NotificationHandler, RequestError,
    RequestHandler, ResponseVerdict, Topic, ValidatorKeyMap,
};
use hyperscale_types::network::gossip::ValidatorAddressGossip;
use hyperscale_types::{
    GossipMessage, MessageClass, NetworkMessage, Request, RoutingCommittees, ShardId, TopicScope,
    TopologySnapshot, ValidatorId,
};
use libp2p::PeerId;
use sbor::{basic_decode, basic_encode};
use tokio::runtime::Handle;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::adapter::Libp2pAdapter;
use crate::address_book::IngestOutcome;
use crate::inbound_router::{InboundRouterHandle, spawn_inbound_router};
use crate::notify_pool::NotifyStreamPool;
use crate::request_manager::RequestError as RmRequestError;

/// Map a transport-level [`RmRequestError`] to the abstract
/// [`RequestError`] without losing variant info — the FSM uses
/// `Exhausted` to skip its own deferral after the transport already
/// retried against rotated peers.
fn translate_request_error(err: RmRequestError) -> RequestError {
    match err {
        RmRequestError::Exhausted { attempts } => RequestError::Exhausted { attempts },
        RmRequestError::NoPeers => RequestError::NoPeers,
        RmRequestError::Network(e) => RequestError::PeerError(format!("{e}")),
        RmRequestError::Shutdown => RequestError::Shutdown,
    }
}
use crate::request_manager::RequestManager;
use crate::request_manager::peer_health::FailureKind;

// ═══════════════════════════════════════════════════════════════════════
// Libp2pNetwork
// ═══════════════════════════════════════════════════════════════════════

/// Production network adapter implementing the Network trait.
///
/// Wraps `Arc<Libp2pAdapter>` and a `RequestManager`. The broadcast path
/// clones the message and offloads SBOR encode, LZ4 compress, and the
/// adapter publish call to the tokio blocking pool via
/// [`Self::spawn_publish`]; the shard pinned thread returns from
/// `broadcast_*` after only the local-dispatch tee and a cheap clone.
/// The adapter's `publish` itself is a crossbeam send so the blocking
/// task never waits on libp2p.
///
/// The generic `request<R>()` method SBOR-encodes the request, dispatches
/// to the `RequestManager`, and SBOR-decodes the response.
pub struct Libp2pNetwork {
    adapter: Arc<Libp2pAdapter>,
    request_manager: Arc<RequestManager>,
    tokio_handle: Handle,
    /// Shared handler registry for per-type gossip and request dispatch.
    registry: Arc<HandlerRegistry>,
    /// Shard-scoped gossip type ids seen by `register_gossip_handler`,
    /// recorded so `subscribe_shard` can replay every per-shard topic
    /// for a shard that joins after registration. Registration happens
    /// at init and reconfiguration is single-threaded, so a plain mutex
    /// suffices.
    shard_gossip_types: Mutex<Vec<&'static str>>,
    /// Topology snapshot used to resolve validator identity for outbound
    /// requests. Updated lock-free via [`Self::update_topology`].
    topology_snapshot: Arc<ArcSwap<TopologySnapshot>>,
    /// Terminal-clamped per-shard routing committees, covering live shards
    /// and split parents still draining out of the head. Fetch routing
    /// resolves `shard → committee` here so a request to a dissolved shard
    /// still reaches its draining members. Updated lock-free via
    /// [`Self::update_routing_committees`].
    routing_committees: Arc<ArcSwap<RoutingCommittees>>,
    /// Count of `PeerUnreachable` errors (cold-start diagnostics).
    /// `Arc` so the wire-fetch path can read it from a spawned task that
    /// the local-serve fallback hands off to.
    peer_unreachable_count: Arc<AtomicUsize>,
    /// Persistent per-peer notification stream pool.
    notify_pool: NotifyStreamPool,
    /// Artificial outbound delay applied to gossipsub publishes, matching
    /// the per-peer pools. `Duration::ZERO` in production.
    simulated_outbound_latency: Duration,
    /// Inbound router handle — spawned eagerly at construction. Kept
    /// alive to prevent the background tasks from being aborted; also
    /// the seam for starting/stopping a shard's request accept loop on
    /// reconfiguration.
    inbound_router: InboundRouterHandle,
}

impl Libp2pNetwork {
    /// Build a `Libp2pNetwork` over the supplied swarm adapter and request manager.
    ///
    /// Eagerly spawns the inbound router on `tokio_handle`; the router dispatches
    /// inbound requests / notifications to handlers registered on `registry`.
    pub fn new(
        adapter: Arc<Libp2pAdapter>,
        request_manager: Arc<RequestManager>,
        tokio_handle: Handle,
        registry: Arc<HandlerRegistry>,
        topology_snapshot: Arc<ArcSwap<TopologySnapshot>>,
        simulated_outbound_latency: Duration,
    ) -> Self {
        // Eagerly spawn the inbound router. It will dispatch incoming
        // requests to handlers as they are registered in the registry.
        let _guard = tokio_handle.enter();
        let inbound_router = spawn_inbound_router(&adapter, registry.clone());

        let notify_pool = NotifyStreamPool::new(
            adapter.clone(),
            tokio_handle.clone(),
            simulated_outbound_latency,
        );

        let network = Self {
            adapter,
            request_manager,
            tokio_handle,
            registry,
            shard_gossip_types: Mutex::new(Vec::new()),
            topology_snapshot,
            routing_committees: Arc::new(ArcSwap::from_pointee(RoutingCommittees::new())),
            peer_unreachable_count: Arc::new(AtomicUsize::new(0)),
            notify_pool,
            simulated_outbound_latency,
            inbound_router,
        };

        // The validator address book is a transport concern, so the network
        // registers its own ingest handlers rather than the node layer: the
        // gossip handler brings up the Global topic subscription and covers
        // shard-hosting nodes; the host handler covers a shard-less pool
        // follower, whose warm book is exactly what a later committee draw
        // depends on. Ingest is idempotent, so the overlap on multi-shard
        // hosts is harmless.
        let ingest = Arc::clone(&network.adapter);
        network.register_gossip_handler(move |gossip: ValidatorAddressGossip, _shard: ShardId| {
            match ingest.ingest_validator_address(&gossip) {
                IngestOutcome::Invalid => GossipVerdict::Reject,
                IngestOutcome::Recorded
                | IngestOutcome::Stale
                | IngestOutcome::UnknownValidator => GossipVerdict::Accept,
            }
        });
        let ingest = Arc::clone(&network.adapter);
        network.register_host_gossip_handler(move |gossip: ValidatorAddressGossip| {
            let _ = ingest.ingest_validator_address(&gossip);
        });

        network
    }

    fn validator_peer_id(&self, validator: ValidatorId) -> Option<PeerId> {
        self.adapter.peer_for_validator(validator)
    }

    /// Encode + compress `message` and hand the resulting bytes to the
    /// adapter's publish channel on the tokio blocking pool.
    ///
    /// SBOR encode for a max-size tx-gossip batch is tens of µs and LZ4
    /// compress at ~500 MB/s is another tens of µs — small individually
    /// but enough to be worth keeping off the shard pinned thread, where
    /// every µs spent here is a µs not spent making consensus progress.
    /// The adapter's `publish` itself is a crossbeam send (non-blocking),
    /// so a saturated tokio blocking pool only delays the encode, not
    /// the swarm event loop.
    fn spawn_publish<M: GossipMessage + 'static>(&self, topic: Topic, message: M) {
        let adapter = Arc::clone(&self.adapter);
        let latency = self.simulated_outbound_latency;
        let handle = self.tokio_handle.clone();
        self.tokio_handle.spawn_blocking(move || {
            let data = compress(&basic_encode(&message).expect("SBOR encode failed"));
            let publish = move || {
                if let Err(e) = adapter.publish(&topic, data, M::class()) {
                    warn!(topic = %topic, error = ?e, "Libp2pNetwork: publish failed");
                }
            };
            if latency.is_zero() {
                publish();
            } else {
                // Test clusters only: hold the encoded frame for the simulated
                // one-way delay so gossip paces with the per-peer notify/request
                // pools instead of racing at localhost speed.
                handle.spawn(async move {
                    sleep(latency).await;
                    publish();
                });
            }
        });
    }

    /// The committed terminal-clamped routing committees the request path
    /// resolves peers from — the per-shard serving set the production
    /// supervisor reconciles shard teardown against, so a shard stays
    /// served exactly while it stays routable. Mirrors the value pushed
    /// by [`Network::update_routing_committees`].
    #[must_use]
    pub fn routing_committees(&self) -> Arc<RoutingCommittees> {
        self.routing_committees.load_full()
    }
}

impl Network for Libp2pNetwork {
    fn update_topology(&self, snapshot: Arc<TopologySnapshot>) {
        // Extract a fresh key map for validator-bind verification.
        let keys: ValidatorKeyMap = snapshot
            .global_validator_set()
            .validators
            .iter()
            .map(|v| (v.validator_id, v.public_key))
            .collect();
        self.adapter.update_validator_keys(Arc::new(keys));
        // Cache the snapshot for validator identity. ArcSwap is lock-free;
        // readers in `request` use `.load()`.
        self.topology_snapshot.store(snapshot);
    }

    fn update_routing_committees(&self, committees: Arc<RoutingCommittees>) {
        self.routing_committees.store(Arc::clone(&committees));
        // Every routable committee is a potential cross-shard counterparty whose
        // provisions and execution certificates arrive by unicast, so the
        // whole union is wanted connectivity. The map already extends a
        // recovering shard's entry with its retained cohort, and a freshly
        // drawn committee appears here the moment the beacon fold seats it
        // — this push is what turns those book entries into connections.
        let self_ids: HashSet<ValidatorId> =
            self.adapter.local_validator_ids().iter().copied().collect();
        let wanted: HashSet<ValidatorId> = committees
            .values()
            .flatten()
            .filter(|validator| !self_ids.contains(validator))
            .copied()
            .collect();
        self.adapter.update_wanted_validators(wanted);
    }

    fn broadcast_to_shard<M: GossipMessage + 'static>(&self, shard: ShardId, message: &M) {
        debug_assert_eq!(
            M::SCOPE,
            TopicScope::Shard,
            "broadcast_to_shard requires SCOPE = Shard"
        );
        // Tee to in-process subscribers when we host a vnode in this
        // shard — gossipsub never loops the publication back to the
        // publisher, so colocated vnodes would otherwise miss it. The
        // registry computes the per-vnode fan-out from `hosted_shards`.
        // Cheap: the registry pushes a `HostEvent` onto an unbounded
        // channel; the encode/decode is skipped on the local path.
        let _ = self.registry.local_dispatch_gossip(message, Some(shard));

        // Hand the SBOR encode + LZ4 compress off the caller's thread.
        // The hottest caller is `flush_tx_gossip_batch` on the shard
        // pinned thread; a max-size batch is hundreds of µs of CPU we
        // shouldn't be charging to consensus progress.
        self.spawn_publish(Topic::shard(M::message_type_id(), shard), message.clone());
    }

    fn broadcast_global<M: GossipMessage + 'static>(&self, message: &M) {
        debug_assert_eq!(
            M::SCOPE,
            TopicScope::Global,
            "broadcast_global requires SCOPE = Global"
        );
        // Tee to in-process subscribers — the registry fans into every
        // hosted shard except `M::source_shard`. Gossipsub doesn't loop
        // self-publishes back, so colocated cross-shard vnodes would
        // miss this without the local tee.
        let _ = self.registry.local_dispatch_gossip(message, None);
        self.spawn_publish(Topic::global(M::message_type_id()), message.clone());
    }

    fn register_gossip_handler<M: GossipMessage + 'static>(&self, handler: impl GossipHandler<M>) {
        // Registry owns SBOR decode + per-vnode fan-out — just forward.
        self.registry.register_gossip(handler);

        // Auto-subscribe to the corresponding gossipsub topic(s). Shard-
        // scoped handlers register one topic per hosted shard so a
        // multi-shard host receives gossip for every shard it serves;
        // the type id is recorded so a shard joining later replays the
        // same subscriptions via `subscribe_shard`.
        let topics: Vec<Topic> = match M::SCOPE {
            TopicScope::Shard => {
                self.shard_gossip_types
                    .lock()
                    .expect("shard_gossip_types lock")
                    .push(M::message_type_id());
                self.adapter
                    .local_shards()
                    .iter()
                    .map(|shard| Topic::shard(M::message_type_id(), *shard))
                    .collect()
            }
            TopicScope::Global => vec![Topic::global(M::message_type_id())],
        };
        for topic in topics {
            if let Err(e) = self.adapter.subscribe_topic(topic.to_string()) {
                warn!(
                    message_type = M::message_type_id(),
                    error = ?e,
                    "Failed to subscribe to topic"
                );
            } else {
                info!(topic = %topic, "Subscribed to topic");
            }
        }
    }

    fn register_host_gossip_handler<M: GossipMessage + 'static>(
        &self,
        handler: impl Fn(M) + Send + Sync + 'static,
    ) {
        // Registry owns SBOR decode — just forward. The Global-topic
        // subscription is brought up by the matching `register_gossip_handler`
        // (every host-level type is also a `TopicScope::Global` gossip type),
        // so the inbound dispatch in `gossipsub.rs` invokes this for a
        // shard-less host alongside the per-hosted-shard fan.
        self.registry.register_host_gossip_handler(handler);
    }

    fn subscribe_shard(&self, shard: ShardId) {
        self.registry.add_hosted_shard(shard);
        self.adapter.add_local_shard(shard);
        // Replay every registered shard-scoped gossip type onto the new
        // shard's topics, then bring up its request accept loop.
        let types: Vec<&'static str> = self
            .shard_gossip_types
            .lock()
            .expect("shard_gossip_types lock")
            .clone();
        for type_id in types {
            let topic = Topic::shard(type_id, shard);
            if let Err(e) = self.adapter.subscribe_topic(topic.to_string()) {
                warn!(topic = %topic, error = ?e, "Failed to subscribe to topic");
            } else {
                info!(topic = %topic, "Subscribed to topic");
            }
        }
        let _guard = self.tokio_handle.enter();
        self.inbound_router.start_shard_loop(shard);
    }

    fn unsubscribe_shard(&self, shard: ShardId) {
        self.inbound_router.stop_shard_loop(shard);
        let types: Vec<&'static str> = self
            .shard_gossip_types
            .lock()
            .expect("shard_gossip_types lock")
            .clone();
        for type_id in types {
            let topic = Topic::shard(type_id, shard);
            if let Err(e) = self.adapter.unsubscribe_topic(topic.to_string()) {
                warn!(topic = %topic, error = ?e, "Failed to unsubscribe from topic");
            }
        }
        self.adapter.remove_local_shard(shard);
        self.registry.remove_hosted_shard(shard);
        self.registry.unregister_requests_for_shard(shard);
    }

    fn notify<M: NetworkMessage + 'static>(&self, recipients: &[ValidatorId], message: &M) {
        // Split into local + remote. Local recipients (our own hosted
        // vnodes) never get a `validator_peers` entry from the bind
        // handshake, so without this branch they'd be silently dropped.
        // A single typed dispatch reaches every same-shard vnode.
        let self_ids: HashSet<ValidatorId> =
            self.adapter.local_validator_ids().iter().copied().collect();
        let has_local = recipients.iter().any(|v| self_ids.contains(v));
        if has_local {
            self.registry.local_dispatch_notification(message);
        }

        // Remote: collapse to unique peers (multi-validator bind can map
        // several recipient vids to one peer, and sending twice on the
        // same stream is wasted bandwidth).
        let mut unique_peers: HashSet<PeerId> = HashSet::with_capacity(recipients.len());
        for &validator in recipients {
            if self_ids.contains(&validator) {
                continue;
            }
            let Some(peer_id) = self.validator_peer_id(validator) else {
                warn!(
                    validator = validator.inner(),
                    "No peer ID for notify target, skipping"
                );
                continue;
            };
            unique_peers.insert(peer_id);
        }

        if unique_peers.is_empty() {
            return;
        }
        let sbor = basic_encode(message).expect("SBOR encode failed");
        let compressed = compress(&sbor);
        let type_id = M::message_type_id();
        for peer_id in unique_peers {
            // Fault gate: drop this unicast leg on a partition against the peer
            // or a matching drop rule.
            if self
                .adapter
                .fault_gate()
                .drop_outbound(peer_id, type_id, Tier::Notification)
            {
                continue;
            }
            self.notify_pool.send(peer_id, type_id, compressed.clone());
        }
    }

    fn register_notification_handler<M: NetworkMessage + Clone + 'static>(
        &self,
        handler: impl NotificationHandler<M>,
    ) {
        self.registry.register_notification(handler);
    }

    fn register_request_handler<R: Request + Send + 'static>(
        &self,
        shard: ShardId,
        handler: impl RequestHandler<R>,
    ) where
        R::Response: Send + 'static,
    {
        // Registry owns SBOR decode/encode — just forward.
        self.registry.register_request(shard, handler);
    }

    #[allow(clippy::too_many_lines)] // single dispatch over the request lifecycle (local-serve → wire)
    fn request<R: Request + Clone + 'static>(
        &self,
        shard: ShardId,
        preferred_peer: Option<ValidatorId>,
        request: R,
        class_override: Option<MessageClass>,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
    ) {
        // Capture state for the spawned task: local-serve attempt + wire
        // fallback both run there. Local-serve runs off the pinned thread
        // because handlers may take locks or block on condvars (the
        // provision-dedup handler is the canonical example).
        let registry = self
            .adapter
            .local_shards()
            .contains(&shard)
            .then(|| Arc::clone(&self.registry));
        let topology_snapshot = Arc::clone(&self.topology_snapshot);
        let routing_committees = Arc::clone(&self.routing_committees);
        let adapter = Arc::clone(&self.adapter);
        let rm = Arc::clone(&self.request_manager);
        let peer_unreachable_count = Arc::clone(&self.peer_unreachable_count);

        self.tokio_handle.spawn(async move {
            // Step 1 — local-serve if we host the shard. A non-empty hit
            // is terminal; an empty hit (e.g. our co-located vnode's
            // `ExecCertStore` hasn't admitted the wave yet) falls through
            // to the remote committee. Without this fall-through, a
            // cross-shard packed host would never ask any other peer.
            if let Some(registry) = registry {
                let local_request = request.clone();
                if let Some(response) = registry.local_dispatch_request::<R>(shard, local_request) {
                    if !R::is_empty_response(&response) {
                        let _ = on_response(Ok(response));
                        return;
                    }
                } else {
                    warn!(
                        request_type = R::message_type_id(),
                        shard = shard.inner(),
                        "Local-serve: no handler registered for hosted shard — falling through"
                    );
                }
            }

            // Step 2 — wire fetch. Resolve shard → committee → PeerIds
            // via the topology snapshot and the adapter's validator-bind
            // registry. Filter out every validator-id this host carries —
            // we never round-trip a request through our own peer.
            let type_id = R::message_type_id();
            // Resolve the committee from the terminal-clamped routing map so
            // a request to a split parent draining out of the head still
            // finds its draining members. Fall back to the head snapshot
            // before the first routing-committees push (cold start).
            let routing = routing_committees.load();
            let topology_snapshot = topology_snapshot.load();
            let committee: &[ValidatorId] = routing.get(&shard).map_or_else(
                || topology_snapshot.committee_for_shard(shard),
                Vec::as_slice,
            );
            let self_ids: HashSet<ValidatorId> =
                adapter.local_validator_ids().iter().copied().collect();
            let resolved_peers: Vec<PeerId> = committee
                .iter()
                .filter(|v| !self_ids.contains(v))
                .filter_map(|&v| adapter.peer_for_validator(v))
                .collect();

            // Fault gate: drop committee members this host is partitioned from,
            // so a request never reaches the far side of a cut. An empty result
            // falls into the `PeerUnreachable` branch below.
            let resolved_peers: Vec<PeerId> = {
                let mut peers = resolved_peers;
                peers.retain(|peer| !adapter.fault_gate().blocked_outbound(*peer));
                peers
            };

            if resolved_peers.is_empty() {
                let count = peer_unreachable_count.fetch_add(1, Ordering::Relaxed);
                if count == 0 {
                    info!(
                        request_type = type_id,
                        shard = shard.inner(),
                        committee_size = committee.len(),
                        "No validator-to-peer mappings resolved yet \
                         (expected during cold start, protocol-level retries will resolve)"
                    );
                } else if count.is_multiple_of(100) {
                    warn!(
                        request_type = type_id,
                        shard = shard.inner(),
                        total_unreachable = count,
                        "PeerUnreachable errors continue (validator-bind still in progress)"
                    );
                }
                let _ = on_response(Err(RequestError::PeerUnreachable(
                    preferred_peer.unwrap_or(ValidatorId::new(0)),
                )));
                return;
            }

            let preferred_libp2p = preferred_peer.and_then(|v| adapter.peer_for_validator(v));
            let class = class_override.unwrap_or_else(R::class);

            let request_bytes = match basic_encode(&request) {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(error = ?e, "Libp2pNetwork: failed to encode request");
                    let _ =
                        on_response(Err(RequestError::PeerError(format!("encode error: {e:?}"))));
                    return;
                }
            };

            let description = format!("{}({}B)", type_id, request_bytes.len());

            match rm
                .request(
                    &resolved_peers,
                    preferred_libp2p,
                    shard,
                    description,
                    type_id,
                    request_bytes,
                    class,
                )
                .await
            {
                Ok((peer, bytes)) => {
                    let verdict = match basic_decode::<R::Response>(&bytes) {
                        Ok(response) => on_response(Ok(response)),
                        Err(e) => {
                            warn!(error = ?e, "Failed to decode response");
                            on_response(Err(RequestError::PeerError(format!(
                                "decode error: {e:?}"
                            ))))
                        }
                    };
                    if matches!(verdict, ResponseVerdict::Reject) {
                        rm.health_tracker()
                            .record_failure(&peer, FailureKind::Other);
                        record_request_retry("app_rejected");
                    }
                }
                Err(e) => {
                    let _ = on_response(Err(translate_request_error(e)));
                }
            }
        });
    }
}
