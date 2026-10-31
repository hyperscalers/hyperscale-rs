//! Production network adapter implementing the Network trait.
//!
//! [`IrohNetwork`] wraps [`IrohAdapter`] and [`RequestManager`] to provide
//! the [`Network`] interface used by `IoLoop` in the production runner.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};
use hyperscale_metrics::record_request_retry;
use hyperscale_network::compression::compress;
use hyperscale_network::deferred::DEFER_TIMEOUT;
use hyperscale_network::fault::Tier;
use hyperscale_network::retry::is_empty_answer;
use hyperscale_network::{
    Answerers, GossipHandler, HandlerRegistry, Network, NotificationHandler, RequestError,
    RequestHandler, ResponseVerdict, ValidatorKeyMap, Verdict, VerdictKey,
};
use hyperscale_types::{
    GossipMessage, GossipScope, MessageClass, NetworkMessage, Request, RoutingCommittees, ShardId,
    TopologySnapshot, ValidatorId,
};
use iroh::EndpointId;
use tokio::runtime::Handle;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::bind::LocalVnodeIdentity;
use crate::endpoint::{AddVnodeError, IrohAdapter};
use crate::fanout::{Fanout, Scope};
use crate::framing::encode_typed_frame;
use crate::notify::ClassStreams;
use crate::path::Readiness;
use crate::protocol::STREAM_NOTIFY;
use crate::request_manager::{RequestError as RmRequestError, RequestManager};

/// Map a transport-level [`RmRequestError`] to the abstract
/// [`RequestError`] without losing variant info: the caller uses
/// `Exhausted` to skip its own deferral after the transport already retried
/// against rotated peers.
fn translate_request_error(err: RmRequestError) -> RequestError {
    match err {
        RmRequestError::Exhausted { attempts } => RequestError::Exhausted { attempts },
        RmRequestError::NoPeers => RequestError::NoPeers,
        RmRequestError::BackingOff { retry_in } => RequestError::BackingOff { retry_in },
        RmRequestError::Network(e) => RequestError::PeerError(format!("{e}")),
        RmRequestError::Shutdown => RequestError::Shutdown,
    }
}

/// Count an answer the caller refused against the peer that gave it. An
/// empty one says the peer did not hold what was asked; any other says
/// it answered falsely.
fn refuse_answer(rm: &RequestManager, peer: EndpointId, empty: bool) {
    if empty {
        rm.record_rejected(peer);
    } else {
        rm.record_invalid(peer);
    }
    record_request_retry("app_rejected");
}

/// Production network adapter implementing the Network trait over iroh.
///
/// Notifications are encoded and compressed once and queued onto the
/// per-peer stream of their class. Requests are encoded, dispatched through
/// the [`RequestManager`], and their responses decoded. Gossip is handed to
/// in-process subscribers at once and fanned out to its audience off the
/// caller's thread.
pub struct IrohNetwork {
    adapter: Arc<IrohAdapter>,
    request_manager: Arc<RequestManager>,
    tokio_handle: Handle,
    /// Shared handler registry for per-type dispatch.
    registry: Arc<HandlerRegistry>,
    /// Topology snapshot used to resolve a shard's committee before the
    /// first routing committees arrive.
    topology_snapshot: Arc<ArcSwap<TopologySnapshot>>,
    /// Terminal-clamped per-shard routing committees, covering live shards
    /// and split parents still draining out of the head, so a request to a
    /// dissolved shard still reaches its draining members.
    routing_committees: Arc<ArcSwap<RoutingCommittees>>,
    /// Count of `PeerUnreachable` errors (cold-start diagnostics).
    peer_unreachable_count: Arc<AtomicUsize>,
    /// Per-peer, per-class notification streams.
    notify_pool: ClassStreams,
    /// Gossip fan-out. Held here so it lives exactly as long as the
    /// network; the adapter reaches it weakly.
    fanout: Arc<Fanout>,
}

impl IrohNetwork {
    /// Build an `IrohNetwork` over the supplied adapter and request manager.
    /// `registry` must be the one the adapter dispatches inbound streams
    /// through.
    #[must_use]
    pub fn new(
        adapter: Arc<IrohAdapter>,
        request_manager: Arc<RequestManager>,
        tokio_handle: Handle,
        registry: Arc<HandlerRegistry>,
        topology_snapshot: Arc<ArcSwap<TopologySnapshot>>,
        simulated_outbound_latency: Duration,
    ) -> Self {
        let notify_pool = ClassStreams::new(
            Arc::clone(&adapter),
            STREAM_NOTIFY,
            tokio_handle.clone(),
            simulated_outbound_latency,
        );
        let routing_committees = Arc::new(ArcSwap::from_pointee(RoutingCommittees::new()));
        let fanout = Fanout::spawn(
            Arc::clone(&adapter),
            Arc::clone(&registry),
            Arc::clone(&topology_snapshot),
            Arc::clone(&routing_committees),
            tokio_handle.clone(),
            simulated_outbound_latency,
        );
        adapter.install_fanout(&fanout);

        Self {
            adapter,
            request_manager,
            tokio_handle,
            registry,
            topology_snapshot,
            routing_committees,
            peer_unreachable_count: Arc::new(AtomicUsize::new(0)),
            notify_pool,
            fanout,
        }
    }

    /// Host `vnode` from now on, and hand its address record to every host
    /// this one is linked to, each of which pulls its proof once its
    /// topology holds the key.
    ///
    /// # Errors
    ///
    /// As [`IrohAdapter::add_vnode`].
    pub fn add_vnode(&self, vnode: LocalVnodeIdentity) -> Result<(), AddVnodeError> {
        self.adapter.add_vnode(vnode)?;
        for peer in self.adapter.connected_peers() {
            self.fanout.hand_own_records(peer);
        }
        Ok(())
    }

    /// How this host reaches the other members of the committees it sits
    /// in.
    #[must_use]
    pub fn readiness(&self) -> Readiness {
        self.fanout.readiness()
    }

    /// The committed terminal-clamped routing committees the request path
    /// resolves peers from: the per-shard serving set the production
    /// supervisor reconciles shard teardown against, so a shard stays
    /// served exactly while it stays routable.
    #[must_use]
    pub fn routing_committees(&self) -> Arc<RoutingCommittees> {
        self.routing_committees.load_full()
    }
}

impl Network for IrohNetwork {
    fn update_topology(&self, snapshot: Arc<TopologySnapshot>) {
        let keys: ValidatorKeyMap = snapshot
            .global_validator_set()
            .validators
            .iter()
            .map(|v| (v.validator_id, v.public_key))
            .collect();
        self.adapter.update_validator_keys(Arc::new(keys));
        self.topology_snapshot.store(snapshot);
    }

    fn settle(&self, key: VerdictKey, verdict: Verdict) {
        self.registry.settle(key, &verdict);
        self.fanout.settle(key, verdict);
    }

    fn update_routing_committees(&self, committees: Arc<RoutingCommittees>) {
        self.routing_committees.store(Arc::clone(&committees));
        // Every routable committee is a potential cross-shard counterparty
        // whose provisions and execution certificates arrive by unicast, so
        // the whole union is wanted connectivity.
        let self_ids: HashSet<ValidatorId> =
            self.adapter.local_validator_ids().iter().copied().collect();
        let wanted: BTreeSet<ValidatorId> = committees
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
            GossipScope::Shard,
            "broadcast_to_shard requires SCOPE = Shard"
        );
        // The transport never sends a publication back to its publisher,
        // so vnodes on this host get it through the registry.
        let _ = self.registry.local_dispatch_gossip(message, Some(shard));
        self.fanout.publish(Scope::Shard(shard), message.clone());
    }

    fn broadcast_global<M: GossipMessage + 'static>(&self, message: &M) {
        debug_assert_eq!(
            M::SCOPE,
            GossipScope::Global,
            "broadcast_global requires SCOPE = Global"
        );
        let _ = self.registry.local_dispatch_gossip(message, None);
        self.fanout.publish(Scope::Global, message.clone());
    }

    fn register_gossip_handler<M: GossipMessage + 'static>(&self, handler: impl GossipHandler<M>) {
        self.registry.register_gossip(handler);
    }

    fn register_host_gossip_handler<M: GossipMessage + 'static>(
        &self,
        handler: impl Fn(M) + Send + Sync + 'static,
    ) {
        self.registry.register_host_gossip_handler(handler);
    }

    fn subscribe_shard(&self, shard: ShardId) {
        self.registry.add_hosted_shard(shard);
        self.adapter.add_local_shard(shard);
    }

    fn unsubscribe_shard(&self, shard: ShardId) {
        self.adapter.remove_local_shard(shard);
        self.registry.remove_hosted_shard(shard);
        self.registry.unregister_requests_for_shard(shard);
    }

    fn notify<M: NetworkMessage + 'static>(&self, recipients: &[ValidatorId], message: &M) {
        // Local recipients (our own hosted vnodes) are never bound to a
        // peer, so they are served by one typed in-process dispatch.
        let self_ids: HashSet<ValidatorId> =
            self.adapter.local_validator_ids().iter().copied().collect();
        if recipients.iter().any(|v| self_ids.contains(v)) {
            self.registry.local_dispatch_notification(message);
        }

        // Remote: collapse to unique peers. Several recipient validators
        // can sit behind one endpoint, and one frame serves them all.
        let mut unique_peers: BTreeSet<EndpointId> = BTreeSet::new();
        for &validator in recipients {
            if self_ids.contains(&validator) {
                continue;
            }
            let Some(peer) = self.adapter.peer_for_validator(validator) else {
                warn!(
                    validator = validator.inner(),
                    "No bound peer for notify target, skipping"
                );
                continue;
            };
            unique_peers.insert(peer);
        }
        if unique_peers.is_empty() {
            return;
        }

        let type_id = M::message_type_id();
        let compressed = compress(&hbor_to_vec(message).expect("wire encode failed"));
        let frame = match encode_typed_frame(type_id, &compressed) {
            Ok(frame) => Bytes::from(frame),
            Err(error) => {
                warn!(type_id, %error, "Cannot frame notification");
                return;
            }
        };
        let class = M::class();
        for peer in unique_peers {
            // Fault gate: drop this unicast leg on a partition against the
            // peer or a matching drop rule.
            if self
                .adapter
                .fault_gate()
                .drop_outbound(peer, type_id, Tier::Notification)
            {
                continue;
            }
            self.notify_pool.send(peer, class, frame.clone());
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
        self.registry.register_request(shard, handler);
    }

    #[allow(clippy::too_many_lines)] // single dispatch over the request lifecycle (local-serve → wire)
    fn request_from<R: Request + Clone + 'static>(
        &self,
        shard: ShardId,
        answerers: Answerers,
        preferred_peer: Option<ValidatorId>,
        request: R,
        class_override: Option<MessageClass>,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
    ) {
        // Local-serve runs off the caller's thread because handlers may
        // take locks or block on condvars.
        let registry = (answerers == Answerers::LocalFirst
            && self.adapter.local_shards().contains(&shard))
        .then(|| Arc::clone(&self.registry));
        let topology_snapshot = Arc::clone(&self.topology_snapshot);
        let routing_committees = Arc::clone(&self.routing_committees);
        let adapter = Arc::clone(&self.adapter);
        let rm = Arc::clone(&self.request_manager);
        let answers = Arc::clone(&self.registry);
        let peer_unreachable_count = Arc::clone(&self.peer_unreachable_count);

        self.tokio_handle.spawn(async move {
            // Step 1: local-serve if we host the shard and the caller has
            // not asked past its own seats. A non-empty hit is
            // terminal; an empty hit falls through to the remote committee,
            // or a host packed across shards would never ask another peer.
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
                        "Local-serve: no handler registered for hosted shard; falling through"
                    );
                }
            }

            // Step 2: wire fetch. Resolve the committee from the
            // terminal-clamped routing map, falling back to the head
            // snapshot before the first routing committees arrive, and
            // leave out every validator this host carries.
            let type_id = R::message_type_id();
            let routing = routing_committees.load();
            let topology_snapshot = topology_snapshot.load();
            let committee: &[ValidatorId] = routing.get(&shard).map_or_else(
                || topology_snapshot.committee_for_shard(shard),
                Vec::as_slice,
            );
            let self_ids: HashSet<ValidatorId> =
                adapter.local_validator_ids().iter().copied().collect();
            // Fault gate: drop committee members this host is partitioned
            // from, so a request never reaches the far side of a cut.
            let resolved_peers: Vec<EndpointId> = committee
                .iter()
                .filter(|v| !self_ids.contains(v))
                .filter_map(|&v| adapter.peer_for_validator(v))
                .filter(|peer| !adapter.fault_gate().blocked_outbound(*peer))
                .collect();

            if resolved_peers.is_empty() {
                let count = peer_unreachable_count.fetch_add(1, Ordering::Relaxed);
                if count == 0 {
                    info!(
                        request_type = type_id,
                        shard = shard.inner(),
                        committee_size = committee.len(),
                        "No validator is bound to a peer yet \
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

            let preferred = preferred_peer.and_then(|v| adapter.peer_for_validator(v));
            let class = class_override.unwrap_or_else(R::class);

            let request_bytes = match hbor_to_vec(&request) {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(error = ?e, "IrohNetwork: failed to encode request");
                    let _ =
                        on_response(Err(RequestError::PeerError(format!("encode error: {e:?}"))));
                    return;
                }
            };
            let description = format!("{}({}B)", type_id, request_bytes.len());

            match rm
                .request(
                    &resolved_peers,
                    preferred,
                    shard,
                    description,
                    type_id,
                    request_bytes,
                    class,
                    is_empty_answer::<R>,
                )
                .await
            {
                Ok((peer, bytes)) => {
                    // An answer that does not decode says the peer answered
                    // falsely. A deferred verdict scores the peer once the
                    // checks it waits on settle.
                    match hbor_from_slice::<R::Response>(&bytes) {
                        Ok(response) => {
                            let empty = R::is_empty_response(&response);
                            match on_response(Ok(response)) {
                                ResponseVerdict::Accept => {}
                                ResponseVerdict::Reject => refuse_answer(&rm, peer, empty),
                                ResponseVerdict::Defer(deferral) => {
                                    let score = Box::new(move |verdict: &Verdict| {
                                        if *verdict == Verdict::Reject {
                                            refuse_answer(&rm, peer, empty);
                                        }
                                    });
                                    if let Some(id) = answers.await_answer(&deferral, score) {
                                        sleep(DEFER_TIMEOUT).await;
                                        answers.expire_answer(id);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = ?e, "Failed to decode response");
                            let _ = on_response(Err(RequestError::PeerError(format!(
                                "decode error: {e:?}"
                            ))));
                            rm.record_invalid(peer);
                            record_request_retry("app_rejected");
                        }
                    }
                }
                Err(e) => {
                    let _ = on_response(Err(translate_request_error(e)));
                }
            }
        });
    }
}
