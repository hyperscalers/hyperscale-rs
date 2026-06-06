//! Per-message-type handler registry with typed registration.
//!
//! Stores gossip and request handlers keyed by `message_type_id`.
//! Both production and simulation network backends share a registry
//! instance between the Network impl and the transport layer.
//!
//! The typed `register_gossip<M>` / `register_request<R>` methods
//! handle SBOR encode/decode, so `Network` impls just forward calls.
//!
//! Handlers are stored as type-erased closures. Typed wrappers are
//! created by the typed registration methods in this module.
//!
//! All registrations happen at init (before any messages arrive), so
//! the read path is lock-free: each map is an `ArcSwap<HashMap<_, _>>`
//! that `register_*` clones-modifies-stores under the implicit init
//! serialization, and `get_*` resolves with a single atomic load.

use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;

use arc_swap::ArcSwap;
use hyperscale_types::{GossipMessage, NetworkMessage, Request, ShardGroupId, TopicScope};
use quick_cache::sync::Cache as QuickCache;
use sbor::{basic_decode, basic_encode};

use crate::traits::{GossipHandler, GossipVerdict, NotificationHandler, RequestHandler};

/// Type-erased gossip handler: receives decompressed SBOR bytes plus the
/// shard the topic encoded (`None` for global-scoped topics), returns
/// verdict.
pub type RawGossipHandler = dyn Fn(Vec<u8>, Option<ShardGroupId>) -> GossipVerdict + Send + Sync;

/// Type-erased notification handler: receives decompressed SBOR bytes, no return value.
pub type RawNotificationHandler = dyn Fn(Vec<u8>) + Send + Sync;

/// Type-erased request handler: receives SBOR request bytes, returns SBOR response bytes.
pub type RawRequestHandler = dyn Fn(&[u8]) -> Vec<u8> + Send + Sync;

/// Insert into an [`ArcSwap`]-backed map by cloning the current snapshot,
/// inserting, and publishing the new map. All registrations happen
/// serially at init, so the load → clone → store sequence is safe
/// without a CAS retry; callers assert any prior-value invariant they
/// want at the call site.
fn arcswap_insert<K, V>(target: &ArcSwap<HashMap<K, V>>, key: K, value: V) -> Option<V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    let mut new = (**target.load()).clone();
    let prior = new.insert(key, value);
    target.store(Arc::new(new));
    prior
}

/// Dispatch a typed gossip message into its handler without SBOR
/// encode/decode. Used by network backends to deliver locally-published
/// messages to in-process subscribers.
pub trait LocalGossipDispatcher: Send + Sync {
    /// Dispatch `msg` (downcast from `&dyn Any` to the registered `M`)
    /// to the typed handler. The handler consumes `M`, so the dispatcher
    /// clones internally. `shard` is the broadcast target shard for
    /// shard-scoped messages and `None` for global-scoped messages.
    fn dispatch(&self, msg: &dyn Any, shard: Option<ShardGroupId>) -> GossipVerdict;
}

/// Counterpart to [`LocalGossipDispatcher`] for fire-and-forget notifications.
pub trait LocalNotificationDispatcher: Send + Sync {
    /// Dispatch `msg` (downcast from `&dyn Any` to the registered `M`)
    /// to the typed handler.
    fn dispatch(&self, msg: &dyn Any);
}

/// Counterpart to [`LocalGossipDispatcher`] for request-response.
///
/// Takes ownership of the typed request (so callers don't have to
/// clone) and returns the typed response as `Box<dyn Any + Send>` for
/// the caller to downcast back. Skipping SBOR keeps `Arc`-shared
/// payloads (transactions, finalized waves, execution certificates)
/// reference-counted instead of deep-copied through bytes.
pub trait LocalRequestDispatcher: Send + Sync {
    /// Dispatch a boxed-Any request to the typed handler. The dispatcher
    /// downcasts `req` to the registered request type, calls the handler,
    /// and boxes the response. Panics if the downcast fails — a wrong
    /// type means the caller looked up a `(TypeId, shard)` slot for one
    /// `R` and then tried to dispatch a different `R`.
    fn dispatch(&self, req: Box<dyn Any + Send>) -> Box<dyn Any + Send>;
}

/// Capacity for the per-type [`GossipMessage::dedup_key`] cache. Sized
/// for a few rounds of committee-size N publishes per type, well bounded.
const DEDUP_CACHE_CAPACITY: usize = 1024;

struct TypedGossipDispatcher<M, H> {
    handler: Arc<H>,
    hosted_shards: Arc<HashSet<ShardGroupId>>,
    /// Content-key dedup cache (see [`GossipMessage::dedup_key`]). Idle
    /// for types whose `dedup_key` returns `None`.
    dedup: QuickCache<u64, ()>,
    _phantom: PhantomData<fn() -> M>,
}

impl<M, H> TypedGossipDispatcher<M, H>
where
    M: GossipMessage + 'static,
    H: GossipHandler<M>,
{
    /// Compute the per-message target hosted-shard set.
    ///
    /// - `Shard` messages: the topic's shard, if hosted.
    /// - `Global` messages: every hosted shard except [`GossipMessage::source_shard`].
    fn target_shards(&self, msg: &M, topic_shard: Option<ShardGroupId>) -> Vec<ShardGroupId> {
        match M::SCOPE {
            TopicScope::Shard => match topic_shard {
                Some(s) if self.hosted_shards.contains(&s) => vec![s],
                _ => Vec::new(),
            },
            TopicScope::Global => {
                let src = msg.source_shard();
                self.hosted_shards
                    .iter()
                    .copied()
                    .filter(|s| Some(*s) != src)
                    .collect()
            }
        }
    }

    /// Check the dedup cache for `msg`. Returns `true` if dispatch
    /// should proceed (key was new or type opts out of dedup), `false`
    /// if the message is a duplicate and the caller should short-circuit.
    ///
    /// `QuickCache` has no atomic insert-if-absent, so two concurrent
    /// calls with the same key may both observe "not present" and both
    /// dispatch. The downstream handler's app-level dedup absorbs this;
    /// the cache is purely a perf optimization.
    fn admit(&self, msg: &M) -> bool {
        let Some(key) = msg.dedup_key() else {
            return true;
        };
        if self.dedup.get(&key).is_some() {
            false
        } else {
            self.dedup.insert(key, ());
            true
        }
    }

    fn dispatch_to_targets(&self, typed: &M, targets: &[ShardGroupId]) -> GossipVerdict {
        let mut verdict = GossipVerdict::Accept;
        for &target in targets {
            if self.handler.on_message(typed.clone(), target) == GossipVerdict::Reject {
                verdict = GossipVerdict::Reject;
            }
        }
        verdict
    }
}

impl<M, H> LocalGossipDispatcher for TypedGossipDispatcher<M, H>
where
    M: GossipMessage + 'static,
    H: GossipHandler<M>,
{
    fn dispatch(&self, msg: &dyn Any, shard: Option<ShardGroupId>) -> GossipVerdict {
        let typed = msg
            .downcast_ref::<M>()
            .expect("local gossip dispatch type mismatch");
        if !self.admit(typed) {
            return GossipVerdict::Accept;
        }
        let targets = self.target_shards(typed, shard);
        self.dispatch_to_targets(typed, &targets)
    }
}

struct TypedNotificationDispatcher<M, H> {
    handler: Arc<H>,
    _phantom: PhantomData<fn() -> M>,
}

impl<M, H> LocalNotificationDispatcher for TypedNotificationDispatcher<M, H>
where
    M: NetworkMessage + Clone + 'static,
    H: NotificationHandler<M>,
{
    fn dispatch(&self, msg: &dyn Any) {
        let typed = msg
            .downcast_ref::<M>()
            .expect("local notification dispatch type mismatch");
        self.handler.on_notification(typed.clone());
    }
}

struct TypedRequestDispatcher<R, H> {
    handler: Arc<H>,
    _phantom: PhantomData<fn() -> R>,
}

impl<R, H> LocalRequestDispatcher for TypedRequestDispatcher<R, H>
where
    R: Request + Send + 'static,
    R::Response: Send + 'static,
    H: RequestHandler<R>,
{
    fn dispatch(&self, req: Box<dyn Any + Send>) -> Box<dyn Any + Send> {
        let typed = req
            .downcast::<R>()
            .expect("local request dispatch type mismatch");
        let response = self.handler.handle_request(*typed);
        Box::new(response)
    }
}

/// Registry of per-message-type handlers.
///
/// Shared between the `Network` impl (which registers handlers) and
/// the transport layer (which dispatches incoming messages).
///
/// Three maps: `gossip`, `request`, and `notification`. A message type
/// can be registered in multiple maps simultaneously.
///
/// Requests are keyed by `(type_id, ShardGroupId)`: a multi-shard host
/// registers one handler per hosted shard so each closure can capture
/// its own `ShardIo`'s storage. Gossip and notifications stay flat
/// because the registry computes the per-vnode fan-out itself, using
/// [`HandlerRegistry::hosted_shards`] supplied at construction:
///
/// - [`TopicScope::Shard`] messages dispatch to the topic's shard if it
///   is hosted, otherwise dropped (we still `Accept` to forward to peers).
/// - [`TopicScope::Global`] messages fan into every hosted shard except
///   [`GossipMessage::source_shard`], so a vnode in a cross-shard pack
///   sees its peer's commits without the handler closure encoding any
///   routing logic.
pub struct HandlerRegistry {
    /// Shards hosted by the owning process. Drives the per-vnode
    /// fan-out inside [`TypedGossipDispatcher`].
    hosted_shards: Arc<HashSet<ShardGroupId>>,
    gossip: ArcSwap<HashMap<&'static str, Arc<RawGossipHandler>>>,
    request: ArcSwap<HashMap<(&'static str, ShardGroupId), Arc<RawRequestHandler>>>,
    notification: ArcSwap<HashMap<&'static str, Arc<RawNotificationHandler>>>,
    /// Typed gossip dispatchers keyed by message `TypeId` for
    /// zero-encode local delivery to colocated subscribers.
    local_gossip: ArcSwap<HashMap<TypeId, Arc<dyn LocalGossipDispatcher>>>,
    /// Typed notification dispatchers (same role as `local_gossip`).
    local_notification: ArcSwap<HashMap<TypeId, Arc<dyn LocalNotificationDispatcher>>>,
    /// Typed request dispatchers keyed by `(TypeId, ShardGroupId)` for
    /// in-process request serving. Used when a host carries a vnode in
    /// the target shard — bypasses libp2p and preserves `Arc`-shared
    /// payloads on the response.
    local_request: ArcSwap<HashMap<(TypeId, ShardGroupId), Arc<dyn LocalRequestDispatcher>>>,
}

impl HandlerRegistry {
    /// Create a registry serving the given hosted shards.
    #[must_use]
    pub fn new(hosted_shards: Arc<HashSet<ShardGroupId>>) -> Self {
        Self {
            hosted_shards,
            gossip: ArcSwap::from_pointee(HashMap::new()),
            request: ArcSwap::from_pointee(HashMap::new()),
            notification: ArcSwap::from_pointee(HashMap::new()),
            local_gossip: ArcSwap::from_pointee(HashMap::new()),
            local_notification: ArcSwap::from_pointee(HashMap::new()),
            local_request: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// Shards hosted by the registry's owner.
    #[must_use]
    pub const fn hosted_shards(&self) -> &Arc<HashSet<ShardGroupId>> {
        &self.hosted_shards
    }

    // ── Typed registration (used by Network impls) ──

    /// Register a typed gossip handler for a message type.
    ///
    /// SBOR-decodes the payload (wire path only), then dispatches the
    /// user handler once per target hosted shard as computed by
    /// [`TypedGossipDispatcher::target_shards`]. The handler closure
    /// makes no routing decisions and sees only well-formed
    /// `(message, target_shard)` pairs.
    ///
    /// # Panics
    ///
    /// Panics if a handler is already registered for this message type. All
    /// registrations happen once at init; a duplicate is a programmer error.
    pub fn register_gossip<M>(&self, handler: impl GossipHandler<M>)
    where
        M: GossipMessage + 'static,
    {
        let dispatcher = Arc::new(TypedGossipDispatcher::<M, _> {
            handler: Arc::new(handler),
            hosted_shards: Arc::clone(&self.hosted_shards),
            dedup: QuickCache::new(DEDUP_CACHE_CAPACITY),
            _phantom: PhantomData,
        });

        let bytes_dispatcher = Arc::clone(&dispatcher);
        let raw: Arc<RawGossipHandler> =
            Arc::new(move |payload: Vec<u8>, shard: Option<ShardGroupId>| {
                match basic_decode::<M>(&payload) {
                    Ok(msg) => {
                        if !bytes_dispatcher.admit(&msg) {
                            return GossipVerdict::Accept;
                        }
                        let targets = bytes_dispatcher.target_shards(&msg, shard);
                        if targets.is_empty() {
                            GossipVerdict::Accept
                        } else {
                            bytes_dispatcher.dispatch_to_targets(&msg, &targets)
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            message_type = M::message_type_id(),
                            error = ?e,
                            "Failed to SBOR-decode gossip message — rejecting"
                        );
                        GossipVerdict::Reject
                    }
                }
            });
        let prior = arcswap_insert(&self.gossip, M::message_type_id(), raw);
        assert!(
            prior.is_none(),
            "duplicate gossip handler registration for {}",
            M::message_type_id(),
        );

        let typed: Arc<dyn LocalGossipDispatcher> = dispatcher;
        arcswap_insert(&self.local_gossip, TypeId::of::<M>(), typed);
    }

    /// Register a typed request handler for a message type on `shard`.
    ///
    /// A multi-shard host registers one handler per hosted shard; the
    /// inbound router looks up `(type_id, shard)` based on which per-shard
    /// stream protocol the request arrived on.
    ///
    /// Wraps the handler in a closure that SBOR-decodes the request,
    /// calls the handler, and SBOR-encodes the response.
    ///
    /// # Panics
    ///
    /// Panics if a handler is already registered for `(type_id, shard)`.
    /// All registrations happen once at init; a duplicate is a programmer
    /// error.
    pub fn register_request<R: Request + Send + 'static>(
        &self,
        shard: ShardGroupId,
        handler: impl RequestHandler<R>,
    ) where
        R::Response: Send + 'static,
    {
        let handler = Arc::new(handler);

        let bytes_handler = Arc::clone(&handler);
        let raw: Arc<RawRequestHandler> = Arc::new(move |payload: &[u8]| -> Vec<u8> {
            let req = match basic_decode::<R>(payload) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        message_type = R::message_type_id(),
                        error = ?e,
                        "Failed to SBOR-decode request — returning empty response"
                    );
                    return vec![];
                }
            };
            let response = bytes_handler.handle_request(req);
            match basic_encode(&response) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(
                        message_type = R::message_type_id(),
                        error = ?e,
                        "Failed to SBOR-encode response — returning empty response"
                    );
                    vec![]
                }
            }
        });

        let prior = arcswap_insert(&self.request, (R::message_type_id(), shard), raw);
        assert!(
            prior.is_none(),
            "duplicate request handler registration for ({}, {shard:?})",
            R::message_type_id(),
        );

        let typed: Arc<dyn LocalRequestDispatcher> = Arc::new(TypedRequestDispatcher::<R, _> {
            handler,
            _phantom: PhantomData,
        });
        arcswap_insert(&self.local_request, (TypeId::of::<R>(), shard), typed);
    }

    /// Register a typed notification handler for a message type.
    ///
    /// SBOR-decodes the payload before calling the handler. Stored in a separate
    /// map so a message type can be registered as both gossip and notification.
    ///
    /// # Panics
    ///
    /// Panics if a handler is already registered for this message type. All
    /// registrations happen once at init; a duplicate is a programmer error.
    pub fn register_notification<M>(&self, handler: impl NotificationHandler<M>)
    where
        M: NetworkMessage + Clone + 'static,
    {
        let handler = Arc::new(handler);

        let bytes_handler = Arc::clone(&handler);
        let raw: Arc<RawNotificationHandler> =
            Arc::new(move |payload: Vec<u8>| match basic_decode::<M>(&payload) {
                Ok(msg) => bytes_handler.on_notification(msg),
                Err(e) => {
                    tracing::warn!(
                        message_type = M::message_type_id(),
                        error = ?e,
                        "Failed to SBOR-decode notification message — dropping"
                    );
                }
            });
        let prior = arcswap_insert(&self.notification, M::message_type_id(), raw);
        assert!(
            prior.is_none(),
            "duplicate notification handler registration for {}",
            M::message_type_id(),
        );

        let typed: Arc<dyn LocalNotificationDispatcher> =
            Arc::new(TypedNotificationDispatcher::<M, _> {
                handler,
                _phantom: PhantomData,
            });
        arcswap_insert(&self.local_notification, TypeId::of::<M>(), typed);
    }

    // ── Raw registration (used by infrastructure tests) ──

    /// Register a raw gossip handler by `type_id` string.
    ///
    /// Prefer [`register_gossip`](Self::register_gossip) for production code.
    /// This is useful for infrastructure tests that work with raw bytes.
    pub fn register_raw_gossip(&self, type_id: &'static str, handler: Arc<RawGossipHandler>) {
        arcswap_insert(&self.gossip, type_id, handler);
    }

    /// Register a raw request handler for `(type_id, shard)`.
    ///
    /// Prefer [`register_request`](Self::register_request) for production code.
    /// This is useful for infrastructure tests that work with raw bytes.
    pub fn register_raw_request(
        &self,
        type_id: &'static str,
        shard: ShardGroupId,
        handler: Arc<RawRequestHandler>,
    ) {
        arcswap_insert(&self.request, (type_id, shard), handler);
    }

    /// Register a raw notification handler by `type_id` string.
    ///
    /// Prefer [`register_notification`](Self::register_notification) for production code.
    /// This is useful for infrastructure tests that work with raw bytes.
    pub fn register_raw_notification(
        &self,
        type_id: &'static str,
        handler: Arc<RawNotificationHandler>,
    ) {
        arcswap_insert(&self.notification, type_id, handler);
    }

    // ── Transport-layer dispatch (used by inbound router / sim harness) ──

    /// Look up the gossip handler for a message type.
    #[must_use]
    pub fn get_gossip(&self, message_type_id: &str) -> Option<Arc<RawGossipHandler>> {
        self.gossip.load().get(message_type_id).cloned()
    }

    /// Look up the request handler for `(type_id, shard)`.
    #[must_use]
    pub fn get_request(
        &self,
        message_type_id: &str,
        shard: ShardGroupId,
    ) -> Option<Arc<RawRequestHandler>> {
        self.request.load().get(&(message_type_id, shard)).cloned()
    }

    /// Look up the notification handler for a message type.
    #[must_use]
    pub fn get_notification(&self, message_type_id: &str) -> Option<Arc<RawNotificationHandler>> {
        self.notification.load().get(message_type_id).cloned()
    }

    /// Dispatch a typed gossip message into its in-process handler,
    /// skipping SBOR encode/decode. Returns `None` if no handler for
    /// `M` is registered. Network backends use this to short-circuit
    /// local delivery for messages they publish. `shard` is the
    /// broadcast target shard for shard-scoped publishes and `None`
    /// for global publishes — the handler receives the same value the
    /// inbound libp2p path supplies.
    #[must_use]
    pub fn local_dispatch_gossip<M>(
        &self,
        msg: &M,
        shard: Option<ShardGroupId>,
    ) -> Option<GossipVerdict>
    where
        M: NetworkMessage + 'static,
    {
        self.local_gossip
            .load()
            .get(&TypeId::of::<M>())
            .map(|d| d.dispatch(msg as &dyn Any, shard))
    }

    /// Dispatch a typed notification message into its in-process handler,
    /// skipping SBOR encode/decode. Returns `false` if no handler for
    /// `M` is registered.
    pub fn local_dispatch_notification<M>(&self, msg: &M) -> bool
    where
        M: NetworkMessage + 'static,
    {
        self.local_notification
            .load()
            .get(&TypeId::of::<M>())
            .is_some_and(|d| {
                d.dispatch(msg as &dyn Any);
                true
            })
    }

    /// Dispatch a typed request to its in-process handler, skipping SBOR
    /// encode/decode. Returns `None` if no handler is registered for
    /// `(R, shard)`. Used by network backends to serve requests for
    /// shards the host carries on-process — `Arc`-shared payloads on the
    /// response (transactions, finalized waves, execution certificates)
    /// flow through reference-counted instead of being deep-copied
    /// through SBOR bytes.
    ///
    /// # Panics
    ///
    /// Panics if the registered dispatcher returns a response that
    /// doesn't downcast to `R::Response`. The registry slot is keyed by
    /// `(TypeId::of::<R>(), shard)`, so this only fires on a programmer
    /// error in registration — not on a runtime input.
    pub fn local_dispatch_request<R>(&self, shard: ShardGroupId, req: R) -> Option<R::Response>
    where
        R: Request + Send + 'static,
        R::Response: Send + 'static,
    {
        let dispatcher = self
            .local_request
            .load()
            .get(&(TypeId::of::<R>(), shard))
            .cloned()?;
        let boxed: Box<dyn Any + Send> = Box::new(req);
        let resp = dispatcher.dispatch(boxed);
        Some(
            *resp
                .downcast::<R::Response>()
                .expect("local request response type mismatch"),
        )
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new(Arc::new(HashSet::new()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn test_register_and_lookup_gossip() {
        use hyperscale_types::NetworkMessage;
        use sbor::{Decode, Encode, basic_encode};

        #[derive(Debug, Clone, Encode, Decode)]
        struct TestMsg(u32);
        impl NetworkMessage for TestMsg {
            fn message_type_id() -> &'static str {
                "test.gossip"
            }
        }
        impl GossipMessage for TestMsg {
            const SCOPE: TopicScope = TopicScope::Shard;
        }

        let hosted = Arc::new(std::iter::once(ShardGroupId::leaf(1, 0)).collect());
        let registry = HandlerRegistry::new(hosted);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        registry.register_gossip(
            move |_msg: TestMsg, _shard: ShardGroupId| -> GossipVerdict {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                GossipVerdict::Accept
            },
        );

        let handler = registry.get_gossip("test.gossip").unwrap();
        let encoded = basic_encode(&TestMsg(42)).unwrap();
        let verdict = handler(encoded, Some(ShardGroupId::leaf(1, 0)));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(verdict, GossipVerdict::Accept);

        // SBOR decode failure should return Reject.
        let verdict = handler(vec![0xFF, 0xFE], Some(ShardGroupId::leaf(1, 0)));
        assert_eq!(verdict, GossipVerdict::Reject);
        assert_eq!(counter.load(Ordering::SeqCst), 1); // handler not called

        assert!(registry.get_gossip("unknown.type").is_none());
    }

    #[test]
    fn test_register_and_lookup_request() {
        use hyperscale_types::{NetworkMessage, Request};
        use sbor::{Decode, Encode, basic_decode, basic_encode};

        #[derive(Debug, Encode, Decode)]
        struct TestReq(u32);
        impl NetworkMessage for TestReq {
            fn message_type_id() -> &'static str {
                "test.request"
            }
        }

        #[derive(Debug, Encode, Decode, PartialEq)]
        struct TestResp(u32);
        impl NetworkMessage for TestResp {
            fn message_type_id() -> &'static str {
                "test.response"
            }
        }

        impl Request for TestReq {
            type Response = TestResp;
        }

        let registry = HandlerRegistry::default();
        let shard = ShardGroupId::leaf(1, 0);

        registry.register_request(shard, |req: TestReq| TestResp(req.0 * 2));

        let handler = registry.get_request("test.request", shard).unwrap();
        let req_bytes = basic_encode(&TestReq(21)).unwrap();
        let response_bytes = handler(&req_bytes);
        let response: TestResp = basic_decode(&response_bytes).unwrap();
        assert_eq!(response, TestResp(42));

        assert!(registry.get_request("unknown.request", shard).is_none());
        assert!(
            registry
                .get_request("test.request", ShardGroupId::leaf(1, 1))
                .is_none()
        );
    }

    #[test]
    #[should_panic(expected = "duplicate gossip handler registration")]
    fn test_double_registration_panics() {
        use hyperscale_types::NetworkMessage;
        use sbor::{Decode, Encode};

        #[derive(Debug, Clone, Encode, Decode)]
        struct TestMsg(u32);
        impl NetworkMessage for TestMsg {
            fn message_type_id() -> &'static str {
                "test"
            }
        }
        impl GossipMessage for TestMsg {
            const SCOPE: TopicScope = TopicScope::Shard;
        }

        let registry = HandlerRegistry::default();
        registry.register_gossip(|_: TestMsg, _shard: ShardGroupId| -> GossipVerdict {
            GossipVerdict::Accept
        });
        registry.register_gossip(|_: TestMsg, _shard: ShardGroupId| -> GossipVerdict {
            GossipVerdict::Accept
        });
    }

    /// A [`Verifiable::Verified`] value handed to [`HandlerRegistry::local_dispatch_gossip`]
    /// must arrive at the handler still in the `Verified` variant. This is the
    /// in-process fast path: colocated vnodes share a trust domain, so a
    /// producer that verified a payload before publishing must not have its
    /// verification thrown away by the dispatch boundary.
    #[test]
    fn local_dispatch_gossip_preserves_verified_marker() {
        use std::sync::Mutex;

        use hyperscale_types::{NetworkMessage, Verifiable, Verified};
        use sbor::prelude::BasicSbor;

        #[derive(Debug, Clone, BasicSbor)]
        struct VTestMsg {
            payload: Verifiable<u32>,
        }

        impl NetworkMessage for VTestMsg {
            fn message_type_id() -> &'static str {
                "test.local_dispatch_verified"
            }
        }
        impl GossipMessage for VTestMsg {
            const SCOPE: TopicScope = TopicScope::Shard;
        }

        let hosted: Arc<HashSet<ShardGroupId>> =
            Arc::new(std::iter::once(ShardGroupId::leaf(1, 0)).collect());
        let registry = HandlerRegistry::new(hosted);

        let observed: Arc<Mutex<Option<Verifiable<u32>>>> = Arc::new(Mutex::new(None));
        let observed_clone = Arc::clone(&observed);

        registry.register_gossip(
            move |msg: VTestMsg, _shard: ShardGroupId| -> GossipVerdict {
                *observed_clone.lock().unwrap() = Some(msg.payload);
                GossipVerdict::Accept
            },
        );

        let verified_msg = VTestMsg {
            payload: Verified::new_unchecked_for_test(42u32).into(),
        };
        let verdict = registry.local_dispatch_gossip(&verified_msg, Some(ShardGroupId::leaf(1, 0)));
        assert_eq!(verdict, Some(GossipVerdict::Accept));

        let received = observed
            .lock()
            .unwrap()
            .clone()
            .expect("local dispatch delivers the payload");
        assert!(
            received.is_verified(),
            "local dispatch must preserve the verified marker across the boundary"
        );
        assert_eq!(*received, 42, "inner value must round-trip");
    }
}
