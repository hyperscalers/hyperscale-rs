//! Production network adapter implementing the Network trait.
//!
//! [`Libp2pNetwork`] wraps [`Libp2pAdapter`] and [`RequestManager`] to provide
//! the [`Network`] interface used by `IoLoop` in the production runner.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwap;
use hyperscale_metrics::record_request_retry;
use hyperscale_network::compression::compress;
use hyperscale_network::{
    GossipHandler, HandlerRegistry, Network, NotificationHandler, RequestError, RequestHandler,
    ResponseVerdict, Topic, TopicScope, ValidatorKeyMap,
};
use hyperscale_types::{
    MessageClass, NetworkMessage, Request, ShardGroupId, ShardMessage, TopologySnapshot,
    ValidatorId,
};
use libp2p::PeerId;
use sbor::{basic_decode, basic_encode};
use tokio::runtime::Handle;
use tracing::{info, warn};

use crate::adapter::Libp2pAdapter;
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
/// Wraps `Arc<Libp2pAdapter>` and SBOR-encodes + LZ4-compresses messages before
/// publishing via the adapter's priority channels. The `publish()` call
/// is sync-safe (non-blocking channel send), so this works from the
/// pinned state machine thread without a tokio runtime context.
///
/// Also owns a `RequestManager` for request-response operations.
/// The generic `request<R>()` method SBOR-encodes the request, dispatches
/// to the `RequestManager`, and SBOR-decodes the response.
pub struct Libp2pNetwork {
    adapter: Arc<Libp2pAdapter>,
    request_manager: Arc<RequestManager>,
    tokio_handle: Handle,
    /// Shared handler registry for per-type gossip and request dispatch.
    registry: Arc<HandlerRegistry>,
    /// Shards hosted by this host. Drives per-shard gossipsub
    /// subscriptions on `register_gossip_handler`.
    local_shards: HashSet<ShardGroupId>,
    /// Topology snapshot used to resolve shard → committee for outbound
    /// requests. Updated lock-free via [`Self::update_topology`].
    topology: Arc<ArcSwap<TopologySnapshot>>,
    /// Count of `PeerUnreachable` errors (cold-start diagnostics).
    peer_unreachable_count: AtomicUsize,
    /// Persistent per-peer notification stream pool.
    notify_pool: NotifyStreamPool,
    /// Inbound router handle — spawned eagerly at construction.
    /// Kept alive to prevent the background task from being aborted.
    _inbound_router: InboundRouterHandle,
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
        topology: Arc<ArcSwap<TopologySnapshot>>,
    ) -> Self {
        // Eagerly spawn the inbound router. It will dispatch incoming
        // requests to handlers as they are registered in the registry.
        let _guard = tokio_handle.enter();
        let inbound_router = spawn_inbound_router(&adapter, registry.clone());

        let notify_pool = NotifyStreamPool::new(adapter.clone(), tokio_handle.clone());

        // Mirror the adapter's hosted-shard set so `register_gossip_handler`
        // can subscribe to one topic per hosted shard without consulting
        // the topology snapshot.
        let local_shards = adapter.local_shards().clone();

        Self {
            adapter,
            request_manager,
            tokio_handle,
            registry,
            local_shards,
            topology,
            peer_unreachable_count: AtomicUsize::new(0),
            notify_pool,
            _inbound_router: inbound_router,
        }
    }

    fn validator_peer_id(&self, validator: ValidatorId) -> Option<PeerId> {
        self.adapter.peer_for_validator(validator)
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
        // Cache the snapshot for shard → committee resolution on outbound
        // requests. ArcSwap is lock-free; readers in `request` use `.load()`.
        self.topology.store(snapshot);
    }

    fn broadcast_to_shard<M: ShardMessage + 'static>(&self, shard: ShardGroupId, message: &M) {
        // Tee to in-process subscribers when we host a vnode in this
        // shard — gossipsub never loops the publication back to the
        // publisher, so colocated vnodes would otherwise miss it. The
        // shard is supplied to the local dispatcher so the handler
        // tags the resulting `NodeInput` with the right hosted shard.
        if self.local_shards.contains(&shard) {
            // Verdict only matters for forwarding decisions; we're the
            // publisher so peer-side gossipsub handles that.
            let _ = self.registry.local_dispatch_gossip(message, Some(shard));
        }
        let topic = Topic::shard(M::message_type_id(), shard);
        let data = compress(&basic_encode(message).expect("SBOR encode failed"));
        if let Err(e) = self.adapter.publish(&topic, data, M::class()) {
            warn!(error = ?e, "Libp2pNetwork: broadcast_to_shard failed");
        }
    }

    fn broadcast_global<M: NetworkMessage + 'static>(&self, message: &M) {
        // Every host subscribes to the global topic, so always tee
        // locally; handlers dedup or self-filter their own emissions.
        // Global-scoped publishes pass `None` as the shard — the
        // handler extracts any relevant shard from the message body.
        let _ = self.registry.local_dispatch_gossip(message, None);
        let topic = Topic::global(M::message_type_id());
        let data = compress(&basic_encode(message).expect("SBOR encode failed"));
        if let Err(e) = self.adapter.publish(&topic, data, M::class()) {
            warn!(error = ?e, "Libp2pNetwork: broadcast_global failed");
        }
    }

    fn register_gossip_handler<M: NetworkMessage + Clone + 'static>(
        &self,
        scope: TopicScope,
        handler: impl GossipHandler<M>,
    ) {
        // Registry owns SBOR decode — just forward.
        self.registry.register_gossip(handler);

        // Auto-subscribe to the corresponding gossipsub topic(s). Shard-
        // scoped handlers register one topic per hosted shard so a
        // multi-shard host receives gossip for every shard it serves.
        let topics: Vec<Topic> = match scope {
            TopicScope::Shard => self
                .local_shards
                .iter()
                .map(|shard| Topic::shard(M::message_type_id(), *shard))
                .collect(),
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
        shard: ShardGroupId,
        handler: impl RequestHandler<R>,
    ) where
        R::Response: Send + 'static,
    {
        // Registry owns SBOR decode/encode — just forward.
        self.registry.register_request(shard, handler);
    }

    fn request<R: Request + 'static>(
        &self,
        shard: ShardGroupId,
        preferred_peer: Option<ValidatorId>,
        request: R,
        class_override: Option<MessageClass>,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
    ) {
        // Local-serve fast path: if `shard` is hosted on-process and a
        // request handler is registered for it, dispatch to the typed
        // handler directly. Skips libp2p, skips SBOR round-trip on both
        // request and response — `Arc`-shared payloads stay shared
        // instead of being deep-copied through bytes. Cross-shard
        // hosting can answer peers it could not otherwise reach (e.g.
        // when it's the only member of `shard`'s committee on this
        // host).
        if self.local_shards.contains(&shard) {
            let registry = Arc::clone(&self.registry);
            // Run off the pinned thread — request handlers may take
            // locks or block on condvars (the provision-dedup handler
            // is the canonical example).
            self.tokio_handle.spawn(async move {
                if let Some(response) = registry.local_dispatch_request::<R>(shard, request) {
                    let _ = on_response(Ok(response));
                } else {
                    // Shouldn't happen: we host the shard but no handler is
                    // registered. Treat as the same error class the wire
                    // path would surface.
                    warn!(
                        request_type = R::message_type_id(),
                        shard = shard.inner(),
                        "Local-serve: no handler registered for hosted shard"
                    );
                    let _ = on_response(Err(RequestError::NoPeers));
                }
            });
            return;
        }

        let type_id = R::message_type_id();

        // Resolve `shard` → committee → libp2p PeerIds via the topology
        // snapshot and the adapter's validator-bind registry. Filter out
        // every validator-id this host carries — we never round-trip a
        // request through our own peer.
        let topology = self.topology.load();
        let committee = topology.committee_for_shard(shard);
        let self_ids: HashSet<ValidatorId> =
            self.adapter.local_validator_ids().iter().copied().collect();
        let resolved_peers: Vec<PeerId> = committee
            .iter()
            .filter(|v| !self_ids.contains(v))
            .filter_map(|&v| self.adapter.peer_for_validator(v))
            .collect();

        if resolved_peers.is_empty() {
            let count = self.peer_unreachable_count.fetch_add(1, Ordering::Relaxed);
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
            // Verdict ignored on the Err path — the network already recorded
            // the failure (or there's nothing to penalize).
            let _ = on_response(Err(RequestError::PeerUnreachable(
                preferred_peer.unwrap_or(ValidatorId::new(0)),
            )));
            return;
        }

        let preferred_libp2p = preferred_peer.and_then(|v| self.validator_peer_id(v));
        let class = class_override.unwrap_or_else(R::class);

        // SBOR-encode for the wire — the local-serve fast path above
        // never reaches here, so the encode cost is only paid when we
        // actually go out to a peer.
        let request_bytes = match basic_encode(&request) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(error = ?e, "Libp2pNetwork: failed to encode request");
                let _ = on_response(Err(RequestError::PeerError(format!("encode error: {e:?}"))));
                return;
            }
        };

        // Pass type_id + SBOR bytes separately — the transport writes the typed frame.
        let description = format!("{}({}B)", type_id, request_bytes.len());
        let rm = self.request_manager.clone();

        self.tokio_handle.spawn(async move {
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
                    // RequestManager returns decompressed SBOR response bytes.
                    // The serving peer is captured so we can deprioritize it
                    // in the health tracker if the app rejects the response.
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
