//! Per-message-type handler registry with typed registration.
//!
//! Stores gossip and request handlers keyed by `message_type_id`.
//! Both production and simulation network backends share a registry
//! instance between the Network impl and the transport layer.
//!
//! The typed `register_gossip<M>` / `register_request<R>` methods
//! handle wire encode/decode, so `Network` impls just forward calls.
//!
//! Handlers are stored as type-erased closures. Typed wrappers are
//! created by the typed registration methods in this module.
//!
//! The read path is lock-free: each map is an `ArcSwap<HashMap<_, _>>`
//! and `get_*` resolves with a single atomic load. Writes (handler
//! registration, per-shard unregistration, hosted-set swaps) clone-
//! modify-store without a CAS retry, which is safe because they are
//! serialized — at init before any messages arrive, and afterwards
//! only from the single thread driving shard reconfiguration.

use std::any::{Any, TypeId};
use std::cell::Cell;
use std::collections::{BTreeSet, HashMap};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};
use hyperscale_types::cache::{BoundedCache, bounded_cache};
use hyperscale_types::{GossipMessage, GossipScope, NetworkMessage, Request, ShardId};

use crate::deferred::{Deferred, WaitId, Waiting};
use crate::traits::{
    Deferral, GossipHandler, NotificationHandler, RequestHandler, Verdict, VerdictKey,
};

thread_local! {
    static LOCAL_DISPATCH: Cell<bool> = const { Cell::new(false) };
}

/// Whether the handler running on this thread was handed its message by
/// this host itself rather than by a peer.
///
/// True inside [`HandlerRegistry`]'s local dispatches. A handler that
/// bounds what peers may queue on this host lets its own messages past
/// that bound.
#[must_use]
pub fn dispatching_locally() -> bool {
    LOCAL_DISPATCH.with(Cell::get)
}

/// Marks the handlers run while it lives as dispatched locally.
struct LocalDispatch(bool);

impl LocalDispatch {
    fn enter() -> Self {
        Self(LOCAL_DISPATCH.with(|local| local.replace(true)))
    }
}

impl Drop for LocalDispatch {
    fn drop(&mut self) {
        LOCAL_DISPATCH.with(|local| local.set(self.0));
    }
}

/// Type-erased gossip handler: receives decompressed wire bytes plus the
/// shard the topic encoded (`None` for global-scoped topics), and returns
/// the verdict of this host's handlers on the message.
///
/// `None` when no handler judged it: it targets no shard this host serves,
/// or its content was dispatched already under another copy's bytes and
/// that copy still stands (see [`GossipMessage::dedup_key`]). A message
/// that does not decode is rejected.
pub type RawGossipHandler = dyn Fn(Vec<u8>, Option<ShardId>) -> Option<Verdict> + Send + Sync;

/// Type-erased host-level gossip handler: receives decompressed wire bytes.
///
/// Invoked once per host for a [`GossipScope::Global`],
/// [`source_shard`](GossipMessage::source_shard) `None` gossip message to
/// deliver it to a shard-less host. Fire and forget — the per-hosted-shard
/// Global fan owns the forward verdict.
pub type RawHostGossipHandler = dyn Fn(Vec<u8>) + Send + Sync;

/// Type-erased notification handler: receives decompressed wire bytes and
/// returns the handler's verdict on the message. A message that does not
/// decode is rejected.
pub type RawNotificationHandler = dyn Fn(Vec<u8>) -> Verdict + Send + Sync;

/// Type-erased request handler: receives request wire bytes, returns response wire bytes.
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

/// Dispatch a typed gossip message into its handler without wire
/// encode/decode. Used by network backends to deliver locally-published
/// messages to in-process subscribers.
pub(crate) trait LocalGossipDispatcher: Send + Sync {
    /// Dispatch `msg` (downcast from `&dyn Any` to the registered `M`)
    /// to the typed handler. The handler consumes `M`, so the dispatcher
    /// clones internally. `shard` is the broadcast target shard for
    /// shard-scoped messages and `None` for global-scoped messages.
    /// `None` when no handler judged the message, as for
    /// [`RawGossipHandler`].
    fn dispatch(&self, msg: &dyn Any, shard: Option<ShardId>) -> Option<Verdict>;

    /// Let a later copy of the content `content` keys reach the handler.
    fn forget(&self, content: u64);
}

/// Counterpart to [`LocalGossipDispatcher`] for the host-level path
/// (see [`HandlerRegistry::register_host_gossip_handler`]). No verdict: the
/// per-hosted-shard Global fan owns it.
pub(crate) trait LocalHostGossipDispatcher: Send + Sync {
    /// Dispatch `msg` (downcast from `&dyn Any` to the registered `M`) to
    /// the host-level handler.
    fn dispatch(&self, msg: &dyn Any);
}

/// Counterpart to [`LocalGossipDispatcher`] for fire-and-forget notifications.
pub(crate) trait LocalNotificationDispatcher: Send + Sync {
    /// Dispatch `msg` (downcast from `&dyn Any` to the registered `M`)
    /// to the typed handler.
    fn dispatch(&self, msg: &dyn Any);
}

/// Counterpart to [`LocalGossipDispatcher`] for request-response.
///
/// Takes ownership of the typed request (so callers don't have to
/// clone) and returns the typed response as `Box<dyn Any + Send>` for
/// the caller to downcast back. Skipping the codec keeps `Arc`-shared
/// payloads (transactions, finalizations, execution certificates)
/// reference-counted instead of deep-copied through bytes.
pub(crate) trait LocalRequestDispatcher: Send + Sync {
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

/// Copies remembered whose content is keyed and whose verdict a check
/// settles later: as many as the dedup caches of a few types hold keys.
const DEFERRED_CACHE_CAPACITY: usize = 4 * DEDUP_CACHE_CAPACITY;

/// The type and content key of each copy whose verdict a check settles
/// later, by the item the check settles.
type DeferredContent = BoundedCache<VerdictKey, (TypeId, u64)>;

/// Definite settlements the answer waits remember. An answer's wait is
/// recorded only once its callback returns, after it has handed the
/// answer to the check that settles it, so a check can finish first; the
/// window spans the few settlements of other items that can land meanwhile
/// many times over.
const ANSWERS_SETTLED_REMEMBERED: usize = 4096;

/// How a transport scores the peer behind an answer whose verdict was
/// deferred, once the checks it waited on settle.
pub type AnswerScore = Box<dyn FnOnce(&Verdict) + Send>;

struct TypedGossipDispatcher<M, H> {
    handler: Arc<H>,
    hosted_shards: Arc<ArcSwap<BTreeSet<ShardId>>>,
    /// Content-key dedup cache (see [`GossipMessage::dedup_key`]). Idle
    /// for types whose `dedup_key` returns `None`. Holds the key of a copy
    /// that was accepted or is still being checked; a copy found false, or
    /// one this host could not judge, gives its key back, so that it does
    /// not shut out a later copy of the same content. Copies differ in what
    /// the content key leaves out, such as a sender and its signature.
    dedup: BoundedCache<u64, ()>,
    /// Where a copy whose verdict a check settles later is remembered,
    /// shared by every type's dispatcher.
    deferred: Arc<DeferredContent>,
    _phantom: PhantomData<fn() -> M>,
}

impl<M, H> TypedGossipDispatcher<M, H>
where
    M: GossipMessage + 'static,
    H: GossipHandler<M>,
{
    /// Compute the per-message target hosted-shard set, loaded fresh so
    /// a shard added or dropped at runtime is observed on the next
    /// message.
    ///
    /// - `Shard` messages: the topic's shard, if hosted.
    /// - `Global` messages: every hosted shard except [`GossipMessage::source_shard`].
    fn target_shards(&self, msg: &M, topic_shard: Option<ShardId>) -> Vec<ShardId> {
        let hosted = self.hosted_shards.load();
        match M::SCOPE {
            GossipScope::Shard => match topic_shard {
                Some(s) if hosted.contains(&s) => vec![s],
                _ => Vec::new(),
            },
            GossipScope::Global => {
                let src = msg.source_shard();
                hosted.iter().copied().filter(|s| Some(*s) != src).collect()
            }
        }
    }

    /// Hand `typed` to the handler once per target and fold the verdicts,
    /// unless a copy of its content was dispatched already and still
    /// stands. `None` when there is no target, or for such a duplicate.
    ///
    /// `BoundedCache` has no atomic insert-if-absent, so two concurrent
    /// calls with the same key may both observe "not present" and both
    /// dispatch. The downstream handler's app-level dedup absorbs this;
    /// the cache is purely a perf optimization.
    fn deliver(&self, typed: &M, topic_shard: Option<ShardId>) -> Option<Verdict> {
        let content = typed.dedup_key();
        if let Some(key) = content {
            if self.dedup.get(&key).is_some() {
                return None;
            }
            self.dedup.insert(key, ());
        }
        let verdict = self
            .target_shards(typed, topic_shard)
            .into_iter()
            .map(|target| self.handler.on_message(typed.clone(), target))
            .reduce(combine_verdicts);
        if let Some(key) = content {
            match &verdict {
                Some(Verdict::Reject | Verdict::Ignore | Verdict::Busy) => {
                    self.dedup.remove(&key);
                }
                Some(Verdict::Defer(deferral)) => {
                    for item in deferral.keys() {
                        self.deferred.insert(*item, (TypeId::of::<M>(), key));
                    }
                }
                Some(Verdict::Accept) | None => {}
            }
        }
        verdict
    }
}

/// The verdict of several hosted shards on one message. A rejection is the
/// sender's fault whatever the other shards made of it; otherwise a shard
/// that accepts the message carries it on, shards still checking it hold it
/// until every one of their checks holds, it is ignored when some shard
/// ignored it and no shard did more, and it is busy only when every shard
/// had no room for it.
fn combine_verdicts(a: Verdict, b: Verdict) -> Verdict {
    match (a, b) {
        (Verdict::Reject, _) | (_, Verdict::Reject) => Verdict::Reject,
        (Verdict::Accept, _) | (_, Verdict::Accept) => Verdict::Accept,
        (Verdict::Defer(a), Verdict::Defer(b)) => Verdict::Defer(a.join(b)),
        (Verdict::Defer(deferral), Verdict::Ignore | Verdict::Busy)
        | (Verdict::Ignore | Verdict::Busy, Verdict::Defer(deferral)) => Verdict::Defer(deferral),
        (Verdict::Ignore, _) | (_, Verdict::Ignore) => Verdict::Ignore,
        (Verdict::Busy, Verdict::Busy) => Verdict::Busy,
    }
}

impl<M, H> LocalGossipDispatcher for TypedGossipDispatcher<M, H>
where
    M: GossipMessage + 'static,
    H: GossipHandler<M>,
{
    fn dispatch(&self, msg: &dyn Any, shard: Option<ShardId>) -> Option<Verdict> {
        let typed = msg
            .downcast_ref::<M>()
            .expect("local gossip dispatch type mismatch");
        self.deliver(typed, shard)
    }

    fn forget(&self, content: u64) {
        self.dedup.remove(&content);
    }
}

struct TypedHostGossipDispatcher<M, F> {
    handler: Arc<F>,
    _phantom: PhantomData<fn() -> M>,
}

impl<M, F> LocalHostGossipDispatcher for TypedHostGossipDispatcher<M, F>
where
    M: GossipMessage + 'static,
    F: Fn(M) + Send + Sync + 'static,
{
    fn dispatch(&self, msg: &dyn Any) {
        let typed = msg
            .downcast_ref::<M>()
            .expect("local host-gossip dispatch type mismatch");
        (self.handler)(typed.clone());
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
        // A message this host sent itself is charged to no one.
        let _ = self.handler.on_notification(typed.clone());
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
/// Requests are keyed by `(type_id, ShardId)`: a multi-shard host
/// registers one handler per hosted shard so each closure can capture
/// its own `ShardIo`'s storage. Gossip and notifications stay flat
/// because the registry computes the per-vnode fan-out itself, using
/// [`HandlerRegistry::hosted_shards`] supplied at construction:
///
/// - [`GossipScope::Shard`] messages dispatch to the topic's shard if it
///   is hosted, otherwise dropped with no verdict.
/// - [`GossipScope::Global`] messages fan into every hosted shard except
///   [`GossipMessage::source_shard`], so a vnode in a cross-shard pack
///   sees its peer's commits without the handler closure encoding any
///   routing logic.
///
/// A message no hosted shard judged carries no verdict, and each backend
/// decides what that means for forwarding.
pub struct HandlerRegistry {
    /// Shards hosted by the owning process. Drives the per-vnode
    /// fan-out inside [`TypedGossipDispatcher`], which loads it per
    /// message; swapped via [`Self::add_hosted_shard`] /
    /// [`Self::remove_hosted_shard`] when shard participation changes.
    hosted_shards: Arc<ArcSwap<BTreeSet<ShardId>>>,
    gossip: ArcSwap<HashMap<&'static str, Arc<RawGossipHandler>>>,
    request: ArcSwap<HashMap<(&'static str, ShardId), Arc<RawRequestHandler>>>,
    notification: ArcSwap<HashMap<&'static str, Arc<RawNotificationHandler>>>,
    /// Per-host gossip handlers keyed by message type id (wire path). A
    /// shard-less host registers a beacon-block handler so the committed-
    /// block broadcast reaches it even with no hosted shards; dispatch is
    /// additive — the per-hosted-shard Global fan is untouched.
    host_gossip: ArcSwap<HashMap<&'static str, Arc<RawHostGossipHandler>>>,
    /// Typed gossip dispatchers keyed by message `TypeId` for
    /// zero-encode local delivery to colocated subscribers.
    local_gossip: ArcSwap<HashMap<TypeId, Arc<dyn LocalGossipDispatcher>>>,
    /// Typed notification dispatchers (same role as `local_gossip`).
    local_notification: ArcSwap<HashMap<TypeId, Arc<dyn LocalNotificationDispatcher>>>,
    /// Typed request dispatchers keyed by `(TypeId, ShardId)` for
    /// in-process request serving. Used when a host carries a vnode in
    /// the target shard — bypasses the transport and preserves
    /// `Arc`-shared payloads on the response.
    local_request: ArcSwap<HashMap<(TypeId, ShardId), Arc<dyn LocalRequestDispatcher>>>,
    /// Typed host-level gossip dispatchers keyed by message `TypeId` for
    /// zero-encode local delivery (counterpart to [`Self::host_gossip`]).
    local_host_gossip: ArcSwap<HashMap<TypeId, Arc<dyn LocalHostGossipDispatcher>>>,
    /// Copies of keyed content whose verdict a check settles later.
    deferred_content: Arc<DeferredContent>,
    /// Answers whose peers wait on a deferred verdict to be scored.
    answers: Mutex<Waiting<AnswerScore>>,
}

impl HandlerRegistry {
    /// Create a registry serving the given hosted shards.
    #[must_use]
    pub fn new(hosted_shards: BTreeSet<ShardId>) -> Self {
        Self {
            hosted_shards: Arc::new(ArcSwap::from_pointee(hosted_shards)),
            gossip: ArcSwap::from_pointee(HashMap::new()),
            request: ArcSwap::from_pointee(HashMap::new()),
            notification: ArcSwap::from_pointee(HashMap::new()),
            host_gossip: ArcSwap::from_pointee(HashMap::new()),
            local_gossip: ArcSwap::from_pointee(HashMap::new()),
            local_notification: ArcSwap::from_pointee(HashMap::new()),
            local_request: ArcSwap::from_pointee(HashMap::new()),
            local_host_gossip: ArcSwap::from_pointee(HashMap::new()),
            deferred_content: Arc::new(bounded_cache(DEFERRED_CACHE_CAPACITY)),
            answers: Mutex::new(Waiting::remembering(ANSWERS_SETTLED_REMEMBERED)),
        }
    }

    /// Shards hosted by the registry's owner (a loaded snapshot).
    #[must_use]
    pub fn hosted_shards(&self) -> Arc<BTreeSet<ShardId>> {
        self.hosted_shards.load_full()
    }

    /// Add one shard to the hosted set. Every gossip dispatcher
    /// observes the new set on its next message; in-flight dispatches
    /// finish against the snapshot they loaded.
    pub fn add_hosted_shard(&self, shard: ShardId) {
        self.hosted_shards.rcu(|set| {
            let mut set = (**set).clone();
            set.insert(shard);
            set
        });
    }

    /// Remove one shard from the hosted set.
    pub fn remove_hosted_shard(&self, shard: ShardId) {
        self.hosted_shards.rcu(|set| {
            let mut set = (**set).clone();
            set.remove(&shard);
            set
        });
    }

    /// Remove every request handler registered for `shard` — both the
    /// wire map and the in-process dispatch map — so a later re-join
    /// can register the shard afresh without tripping the duplicate-
    /// registration assert. Requests already dispatched against the old
    /// snapshot complete against the handlers they resolved.
    pub fn unregister_requests_for_shard(&self, shard: ShardId) {
        let mut wire = (**self.request.load()).clone();
        wire.retain(|(_, s), _| *s != shard);
        self.request.store(Arc::new(wire));

        let mut local = (**self.local_request.load()).clone();
        local.retain(|(_, s), _| *s != shard);
        self.local_request.store(Arc::new(local));
    }

    // ── Typed registration (used by Network impls) ──

    /// Register a typed gossip handler for a message type.
    ///
    /// decodes the payload (wire path only), then dispatches the
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
            dedup: bounded_cache(DEDUP_CACHE_CAPACITY),
            deferred: Arc::clone(&self.deferred_content),
            _phantom: PhantomData,
        });

        let bytes_dispatcher = Arc::clone(&dispatcher);
        let raw: Arc<RawGossipHandler> =
            Arc::new(move |payload: Vec<u8>, shard: Option<ShardId>| {
                match hbor_from_slice::<M>(&payload) {
                    Ok(msg) => bytes_dispatcher.deliver(&msg, shard),
                    Err(e) => {
                        tracing::warn!(
                            message_type = M::message_type_id(),
                            error = ?e,
                            "Failed to decode gossip message — rejecting"
                        );
                        Some(Verdict::Reject)
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

    /// Register a handler invoked once per host for a [`GossipScope::Global`],
    /// [`source_shard`](GossipMessage::source_shard) `None` gossip message
    /// of type `M`, independent of the hosted-shard set.
    ///
    /// A host's beacon loop registers this so a committed beacon block
    /// reaches it whatever shards the host serves, including none, where
    /// the per-hosted-shard Global fan from
    /// [`TypedGossipDispatcher::target_shards`] is empty. Additive: the
    /// per-shard fan is unchanged, and only the source-`None` Global path
    /// gains a delivery.
    ///
    /// # Panics
    ///
    /// Panics if a handler is already registered for this message type. All
    /// registrations happen once at init; a duplicate is a programmer error.
    pub fn register_host_gossip_handler<M>(&self, handler: impl Fn(M) + Send + Sync + 'static)
    where
        M: GossipMessage + 'static,
    {
        let handler = Arc::new(handler);

        let bytes_handler = Arc::clone(&handler);
        let raw: Arc<RawHostGossipHandler> = Arc::new(
            move |payload: Vec<u8>| match hbor_from_slice::<M>(&payload) {
                Ok(msg) => bytes_handler(msg),
                Err(e) => {
                    tracing::warn!(
                        message_type = M::message_type_id(),
                        error = ?e,
                        "Failed to decode host-level gossip — dropping"
                    );
                }
            },
        );
        let prior = arcswap_insert(&self.host_gossip, M::message_type_id(), raw);
        assert!(
            prior.is_none(),
            "duplicate host gossip handler registration for {}",
            M::message_type_id(),
        );

        let typed: Arc<dyn LocalHostGossipDispatcher> =
            Arc::new(TypedHostGossipDispatcher::<M, _> {
                handler,
                _phantom: PhantomData,
            });
        arcswap_insert(&self.local_host_gossip, TypeId::of::<M>(), typed);
    }

    /// Register a typed request handler for a message type on `shard`.
    ///
    /// A multi-shard host registers one handler per hosted shard; the
    /// inbound router looks up `(type_id, shard)` based on which per-shard
    /// stream protocol the request arrived on.
    ///
    /// Wraps the handler in a closure that decodes the request,
    /// calls the handler, and encodes the response.
    ///
    /// # Panics
    ///
    /// Panics if a handler is already registered for `(type_id, shard)`.
    /// All registrations happen once at init; a duplicate is a programmer
    /// error.
    pub fn register_request<R: Request + Send + 'static>(
        &self,
        shard: ShardId,
        handler: impl RequestHandler<R>,
    ) where
        R::Response: Send + 'static,
    {
        let handler = Arc::new(handler);

        let bytes_handler = Arc::clone(&handler);
        let raw: Arc<RawRequestHandler> = Arc::new(move |payload: &[u8]| -> Vec<u8> {
            let req = match hbor_from_slice::<R>(payload) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        message_type = R::message_type_id(),
                        error = ?e,
                        "Failed to decode request — returning empty response"
                    );
                    return vec![];
                }
            };
            let response = bytes_handler.handle_request(req);
            match hbor_to_vec(&response) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(
                        message_type = R::message_type_id(),
                        error = ?e,
                        "Failed to encode response — returning empty response"
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
    /// decodes the payload before calling the handler. Stored in a separate
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
            Arc::new(
                move |payload: Vec<u8>| match hbor_from_slice::<M>(&payload) {
                    Ok(msg) => bytes_handler.on_notification(msg),
                    Err(e) => {
                        tracing::warn!(
                            message_type = M::message_type_id(),
                            error = ?e,
                            "Failed to decode notification message — rejecting"
                        );
                        Verdict::Reject
                    }
                },
            );
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
        shard: ShardId,
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

    /// Look up the host-level gossip handler for a message type (wire path).
    /// A backend's inbound delivery for a [`GossipScope::Global`],
    /// source-`None` message invokes this in addition to the per-shard fan
    /// so a shard-less host folds the message.
    #[must_use]
    pub fn get_host_gossip(&self, message_type_id: &str) -> Option<Arc<RawHostGossipHandler>> {
        self.host_gossip.load().get(message_type_id).cloned()
    }

    /// Look up the request handler for `(type_id, shard)`.
    #[must_use]
    pub fn get_request(
        &self,
        message_type_id: &str,
        shard: ShardId,
    ) -> Option<Arc<RawRequestHandler>> {
        self.request.load().get(&(message_type_id, shard)).cloned()
    }

    /// Look up the notification handler for a message type.
    #[must_use]
    pub fn get_notification(&self, message_type_id: &str) -> Option<Arc<RawNotificationHandler>> {
        self.notification.load().get(message_type_id).cloned()
    }

    /// Dispatch a typed gossip message into its in-process handler,
    /// skipping wire encode/decode. Returns `None` if no handler for
    /// `M` is registered or none judged the message. Network backends use this to short-circuit
    /// local delivery for messages they publish. `shard` is the
    /// broadcast target shard for shard-scoped publishes and `None`
    /// for global publishes — the handler receives the same value the
    /// inbound transport path supplies.
    #[must_use]
    pub fn local_dispatch_gossip<M>(&self, msg: &M, shard: Option<ShardId>) -> Option<Verdict>
    where
        M: NetworkMessage + 'static,
    {
        let _local = LocalDispatch::enter();
        let verdict = self
            .local_gossip
            .load()
            .get(&TypeId::of::<M>())
            .and_then(|d| d.dispatch(msg as &dyn Any, shard));
        // A Global-scoped, source-`None` publish (carried with `shard ==
        // None`) also reaches any registered host-level handler, so a
        // shard-less host folds it even though the per-shard fan is empty.
        if shard.is_none()
            && let Some(host_handler) = self.local_host_gossip.load().get(&TypeId::of::<M>())
        {
            host_handler.dispatch(msg as &dyn Any);
        }
        verdict
    }

    /// Take the settled verdict on the item `key` names (see
    /// [`crate::Network::settle`]): a copy whose check found it false, or
    /// left this host unable to judge it, no longer keeps later copies of
    /// its content from their handlers.
    /// Every answer that waited on it and has its verdict now is scored.
    ///
    /// # Panics
    ///
    /// Panics if the answer waits' lock is poisoned.
    pub fn settle(&self, key: VerdictKey, verdict: &Verdict) {
        let scored = self
            .answers
            .lock()
            .expect("answer waits lock")
            .settle(key, verdict.clone());
        for (score, verdict) in scored {
            score(&verdict);
        }
        let Some((message_type, content)) = self.deferred_content.get(&key) else {
            return;
        };
        self.deferred_content.remove(&key);
        if matches!(verdict, Verdict::Reject | Verdict::Ignore | Verdict::Busy)
            && let Some(dispatcher) = self.local_gossip.load().get(&message_type)
        {
            dispatcher.forget(content);
        }
    }

    /// Hold `score` for an answer whose verdict `deferral` defers, until the
    /// checks it names settle through [`Self::settle`]. Returns the wait for
    /// the transport to give up through [`Self::expire_answer`] after
    /// [`DEFER_TIMEOUT`](crate::deferred::DEFER_TIMEOUT), or `None` when
    /// every check had settled already and `score` has run.
    ///
    /// # Panics
    ///
    /// Panics if the answer waits' lock is poisoned.
    pub fn await_answer(&self, deferral: &Deferral, score: AnswerScore) -> Option<WaitId> {
        let deferred = self
            .answers
            .lock()
            .expect("answer waits lock")
            .defer(deferral.keys(), score);
        match deferred {
            Deferred::Waits(id) => Some(id),
            Deferred::Settled(score, verdict) => {
                score(&verdict);
                None
            }
        }
    }

    /// Give up on the answer wait `id`, if it still waits: its peer is not
    /// scored.
    ///
    /// # Panics
    ///
    /// Panics if the answer waits' lock is poisoned.
    pub fn expire_answer(&self, id: WaitId) {
        self.answers.lock().expect("answer waits lock").expire(id);
    }

    /// How many answers wait on a deferred verdict.
    ///
    /// # Panics
    ///
    /// Panics if the answer waits' lock is poisoned.
    #[must_use]
    pub fn awaited_answers(&self) -> usize {
        self.answers.lock().expect("answer waits lock").len()
    }

    /// Dispatch a typed notification message into its in-process handler,
    /// skipping wire encode/decode. Returns `false` if no handler for
    /// `M` is registered.
    pub fn local_dispatch_notification<M>(&self, msg: &M) -> bool
    where
        M: NetworkMessage + 'static,
    {
        let _local = LocalDispatch::enter();
        self.local_notification
            .load()
            .get(&TypeId::of::<M>())
            .is_some_and(|d| {
                d.dispatch(msg as &dyn Any);
                true
            })
    }

    /// Dispatch a typed request to its in-process handler, skipping wire
    /// encode/decode. Returns `None` if no handler is registered for
    /// `(R, shard)`. Used by network backends to serve requests for
    /// shards the host carries on-process — `Arc`-shared payloads on the
    /// response (transactions, finalizations, execution certificates)
    /// flow through reference-counted instead of being deep-copied
    /// through wire bytes.
    ///
    /// # Panics
    ///
    /// Panics if the registered dispatcher returns a response that
    /// doesn't downcast to `R::Response`. The registry slot is keyed by
    /// `(TypeId::of::<R>(), shard)`, so this only fires on a programmer
    /// error in registration — not on a runtime input.
    pub fn local_dispatch_request<R>(&self, shard: ShardId, req: R) -> Option<R::Response>
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
        Self::new(BTreeSet::new())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hyperscale_types::MessageClass;

    use super::*;

    #[test]
    fn test_register_and_lookup_gossip() {
        use hyperscale_hbor::{Hbor, to_vec as hbor_to_vec};
        use hyperscale_types::NetworkMessage;

        #[derive(Debug, Clone, Hbor)]
        struct TestMsg(u32);
        impl NetworkMessage for TestMsg {
            fn message_type_id() -> &'static str {
                "test.gossip"
            }

            fn class() -> MessageClass {
                MessageClass::Recovery
            }
        }
        impl GossipMessage for TestMsg {
            const SCOPE: GossipScope = GossipScope::Shard;
        }

        let hosted = std::iter::once(ShardId::leaf(1, 0)).collect();
        let registry = HandlerRegistry::new(hosted);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        registry.register_gossip(move |_msg: TestMsg, _shard: ShardId| -> Verdict {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            Verdict::Accept
        });

        let handler = registry.get_gossip("test.gossip").unwrap();
        let encoded = hbor_to_vec(&TestMsg(42)).unwrap();
        let verdict = handler(encoded, Some(ShardId::leaf(1, 0)));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(verdict, Some(Verdict::Accept));

        // Decode failure should return Reject.
        let verdict = handler(vec![0xFF, 0xFE], Some(ShardId::leaf(1, 0)));
        assert_eq!(verdict, Some(Verdict::Reject));
        assert_eq!(counter.load(Ordering::SeqCst), 1); // handler not called

        assert!(registry.get_gossip("unknown.type").is_none());
    }

    #[test]
    fn a_notification_carries_its_handlers_verdict_and_one_that_does_not_decode_is_rejected() {
        use hyperscale_hbor::{Hbor, to_vec as hbor_to_vec};
        use hyperscale_types::NetworkMessage;

        #[derive(Debug, Clone, Hbor)]
        struct Note(u32);
        impl NetworkMessage for Note {
            fn message_type_id() -> &'static str {
                "test.note"
            }

            fn class() -> MessageClass {
                MessageClass::Consensus
            }
        }

        let registry = HandlerRegistry::default();
        registry.register_notification(|note: Note| {
            if note.0 == 0 {
                Verdict::Ignore
            } else {
                Verdict::Accept
            }
        });
        let handler = registry.get_notification("test.note").unwrap();

        assert_eq!(handler(hbor_to_vec(&Note(1)).unwrap()), Verdict::Accept);
        assert_eq!(handler(hbor_to_vec(&Note(0)).unwrap()), Verdict::Ignore);
        assert_eq!(handler(vec![0xFF, 0xFE]), Verdict::Reject);
    }

    #[test]
    fn test_register_and_lookup_request() {
        use hyperscale_hbor::{Hbor, from_slice as hbor_from_slice, to_vec as hbor_to_vec};
        use hyperscale_types::{NetworkMessage, Request};

        #[derive(Debug, Hbor)]
        struct TestReq(u32);
        impl NetworkMessage for TestReq {
            fn message_type_id() -> &'static str {
                "test.request"
            }

            fn class() -> MessageClass {
                MessageClass::Recovery
            }
        }

        #[derive(Debug, Hbor, PartialEq)]
        struct TestResp(u32);
        impl NetworkMessage for TestResp {
            fn message_type_id() -> &'static str {
                "test.response"
            }

            fn class() -> MessageClass {
                MessageClass::Recovery
            }
        }

        impl Request for TestReq {
            type Response = TestResp;
        }

        let registry = HandlerRegistry::default();
        let shard = ShardId::leaf(1, 0);

        registry.register_request(shard, |req: TestReq| TestResp(req.0 * 2));

        let handler = registry.get_request("test.request", shard).unwrap();
        let req_bytes = hbor_to_vec(&TestReq(21)).unwrap();
        let response_bytes = handler(&req_bytes);
        let response: TestResp = hbor_from_slice(&response_bytes).unwrap();
        assert_eq!(response, TestResp(42));

        assert!(registry.get_request("unknown.request", shard).is_none());
        assert!(
            registry
                .get_request("test.request", ShardId::leaf(1, 1))
                .is_none()
        );
    }

    /// Gossip fan-out tracks the hosted-shard set live: a dispatcher
    /// registered before a hosted-set swap routes to the new set on its
    /// next message.
    #[test]
    fn gossip_fanout_observes_hosted_shard_swap() {
        use hyperscale_hbor::{Hbor, to_vec as hbor_to_vec};
        use hyperscale_types::NetworkMessage;

        #[derive(Debug, Clone, Hbor)]
        struct SwapMsg(u32);
        impl NetworkMessage for SwapMsg {
            fn message_type_id() -> &'static str {
                "test.hosted_swap"
            }

            fn class() -> MessageClass {
                MessageClass::Recovery
            }
        }
        impl GossipMessage for SwapMsg {
            const SCOPE: GossipScope = GossipScope::Shard;
        }

        let shard_a = ShardId::leaf(1, 0);
        let shard_b = ShardId::leaf(1, 1);
        let registry = HandlerRegistry::new(std::iter::once(shard_a).collect());
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = Arc::clone(&hits);
        registry.register_gossip(move |_msg: SwapMsg, _shard: ShardId| -> Verdict {
            hits_clone.fetch_add(1, Ordering::SeqCst);
            Verdict::Accept
        });
        let handler = registry.get_gossip("test.hosted_swap").unwrap();
        let encoded = hbor_to_vec(&SwapMsg(1)).unwrap();

        // Shard B isn't hosted — no handler here judges the message.
        assert_eq!(handler(encoded.clone(), Some(shard_b)), None);
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        // After the swap the same registered handler receives shard B and
        // no longer receives shard A.
        registry.add_hosted_shard(shard_b);
        registry.remove_hosted_shard(shard_a);
        let _ = handler(encoded.clone(), Some(shard_b));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let _ = handler(encoded, Some(shard_a));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// A message several hosted shards judge carries the strongest verdict:
    /// any rejection, else any acceptance, else every check the shards
    /// still run, else any shard's ignoring it; it is busy only when every
    /// shard had no room for it.
    #[test]
    fn hosted_shards_verdicts_fold_rejection_first_then_acceptance() {
        use std::sync::Mutex;

        use Verdict::{Accept, Busy, Ignore, Reject};
        use hyperscale_hbor::{Hbor, to_vec as hbor_to_vec};
        use hyperscale_types::NetworkMessage;

        #[derive(Debug, Clone, Hbor)]
        struct FoldMsg(u32);
        impl NetworkMessage for FoldMsg {
            fn message_type_id() -> &'static str {
                "test.fold"
            }

            fn class() -> MessageClass {
                MessageClass::Recovery
            }
        }
        impl GossipMessage for FoldMsg {
            const SCOPE: GossipScope = GossipScope::Global;
        }

        let (a, b) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let registry = HandlerRegistry::new([a, b].into_iter().collect());
        let verdicts: Arc<Mutex<HashMap<ShardId, Verdict>>> = Arc::default();
        let answers = Arc::clone(&verdicts);
        registry.register_gossip(move |_: FoldMsg, shard: ShardId| {
            answers.lock().unwrap()[&shard].clone()
        });
        let handler = registry.get_gossip("test.fold").unwrap();

        let fold = |first: Verdict, second: Verdict| {
            *verdicts.lock().unwrap() = HashMap::from([(a, first), (b, second)]);
            handler(hbor_to_vec(&FoldMsg(1)).unwrap(), None)
        };
        assert_eq!(fold(Accept, Reject), Some(Reject));
        assert_eq!(fold(Ignore, Reject), Some(Reject));
        assert_eq!(fold(Ignore, Accept), Some(Accept));
        assert_eq!(fold(Ignore, Ignore), Some(Ignore));
        assert_eq!(fold(Busy, Accept), Some(Accept));
        assert_eq!(fold(Busy, Ignore), Some(Ignore));
        assert_eq!(fold(Busy, Busy), Some(Busy));

        let (first, second) = (VerdictKey::of(&1u8), VerdictKey::of(&2u8));
        assert_eq!(
            fold(Verdict::defer(first), Verdict::defer(second)),
            Some(Verdict::defer_all([second, first])),
            "a message two shards are checking holds up only when both checks do"
        );
        assert_eq!(
            fold(Verdict::defer(first), Ignore),
            Some(Verdict::defer(first))
        );
        assert_eq!(fold(Verdict::defer(first), Accept), Some(Accept));
        assert_eq!(
            fold(Busy, Verdict::defer(first)),
            Some(Verdict::defer(first))
        );
    }

    /// A copy of some content, as several senders publish it: `content`
    /// is what the dedup key covers, `forged` what the handler finds.
    #[derive(Debug, Clone, hyperscale_hbor::Hbor)]
    struct Copy {
        content: u32,
        sender: u32,
        forged: bool,
    }

    impl NetworkMessage for Copy {
        fn message_type_id() -> &'static str {
            "test.copy"
        }

        fn class() -> MessageClass {
            MessageClass::CrossShardProgress
        }
    }

    impl GossipMessage for Copy {
        const SCOPE: GossipScope = GossipScope::Global;

        fn dedup_key(&self) -> Option<u64> {
            Some(u64::from(self.content))
        }
    }

    /// A registry whose handler for [`Copy`] answers `verdict` for each copy
    /// and counts the copies it is handed.
    fn copies_judged_by(
        verdict: impl Fn(&Copy) -> Verdict + Send + Sync + 'static,
    ) -> (HandlerRegistry, Arc<AtomicUsize>) {
        let registry = HandlerRegistry::new(std::iter::once(ShardId::leaf(1, 0)).collect());
        let handled = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&handled);
        registry.register_gossip(move |copy: Copy, _: ShardId| {
            counted.fetch_add(1, Ordering::SeqCst);
            verdict(&copy)
        });
        (registry, handled)
    }

    fn deliver(registry: &HandlerRegistry, copy: &Copy) -> Option<Verdict> {
        let handler = registry.get_gossip("test.copy").unwrap();
        handler(hbor_to_vec(copy).unwrap(), None)
    }

    fn copy(sender: u32, forged: bool) -> Copy {
        Copy {
            content: 9,
            sender,
            forged,
        }
    }

    #[test]
    fn a_copy_found_false_does_not_shut_out_a_later_honest_one() {
        let (registry, handled) = copies_judged_by(|copy| {
            if copy.forged {
                Verdict::Reject
            } else {
                Verdict::Accept
            }
        });

        assert_eq!(deliver(&registry, &copy(1, true)), Some(Verdict::Reject));
        assert_eq!(deliver(&registry, &copy(2, false)), Some(Verdict::Accept));
        assert_eq!(
            deliver(&registry, &copy(3, false)),
            None,
            "an accepted copy stands for its content"
        );
        assert_eq!(handled.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_copy_this_host_could_not_judge_does_not_shut_out_another() {
        let (registry, handled) = copies_judged_by(|copy| {
            if copy.sender == 1 {
                Verdict::Ignore
            } else {
                Verdict::Accept
            }
        });

        assert_eq!(deliver(&registry, &copy(1, false)), Some(Verdict::Ignore));
        assert_eq!(deliver(&registry, &copy(2, false)), Some(Verdict::Accept));
        assert_eq!(handled.load(Ordering::SeqCst), 2);
    }

    /// An answer's deferred verdict scores it once, when its check
    /// settles, or at once when the check settled before the wait; a
    /// wait given up scores nothing.
    #[test]
    fn a_deferred_answer_is_scored_once_by_its_check() {
        let registry = HandlerRegistry::new(BTreeSet::new());
        let scored = Arc::new(Mutex::new(Vec::new()));
        let score = || -> AnswerScore {
            let scored = Arc::clone(&scored);
            Box::new(move |verdict: &Verdict| scored.lock().unwrap().push(verdict.clone()))
        };
        let (late, early, never) = (
            VerdictKey::of(&1u8),
            VerdictKey::of(&2u8),
            VerdictKey::of(&3u8),
        );
        let deferral = |key| {
            let Verdict::Defer(deferral) = Verdict::defer(key) else {
                unreachable!("a deferral");
            };
            deferral
        };

        assert!(registry.await_answer(&deferral(late), score()).is_some());
        registry.settle(late, &Verdict::Reject);
        registry.settle(late, &Verdict::Reject);
        assert_eq!(*scored.lock().unwrap(), vec![Verdict::Reject]);

        registry.settle(early, &Verdict::Reject);
        assert!(registry.await_answer(&deferral(early), score()).is_none());
        assert_eq!(scored.lock().unwrap().len(), 2, "a check that came first");

        let wait = registry
            .await_answer(&deferral(never), score())
            .expect("nothing settled it");
        assert_eq!(registry.awaited_answers(), 1);
        registry.expire_answer(wait);
        assert_eq!(registry.awaited_answers(), 0);
        registry.settle(never, &Verdict::Reject);
        assert_eq!(scored.lock().unwrap().len(), 2, "a wait given up");
    }

    #[test]
    fn a_deferred_copy_stands_until_its_check_finds_it_false() {
        let key = |copy: &Copy| VerdictKey::of(&(copy.sender, copy.forged));
        let (registry, handled) = copies_judged_by(move |copy| Verdict::defer(key(copy)));

        let forged = copy(1, true);
        assert_eq!(
            deliver(&registry, &forged),
            Some(Verdict::defer(key(&forged)))
        );
        assert_eq!(
            deliver(&registry, &copy(2, false)),
            None,
            "a copy being checked stands for its content"
        );
        registry.settle(key(&forged), &Verdict::Reject);

        let honest = copy(3, false);
        assert_eq!(
            deliver(&registry, &honest),
            Some(Verdict::defer(key(&honest)))
        );
        registry.settle(key(&honest), &Verdict::Accept);
        assert_eq!(
            deliver(&registry, &copy(4, false)),
            None,
            "a copy whose check held stands for its content"
        );
        assert_eq!(handled.load(Ordering::SeqCst), 2);
    }

    /// Per-shard request unregistration clears both dispatch maps and
    /// lets the shard register afresh without tripping the duplicate-
    /// registration assert; other shards' handlers are untouched.
    #[test]
    fn unregister_requests_for_shard_clears_and_allows_rejoin() {
        use hyperscale_hbor::Hbor;
        use hyperscale_types::{NetworkMessage, Request};

        #[derive(Debug, Hbor)]
        struct RejoinReq(u32);
        impl NetworkMessage for RejoinReq {
            fn message_type_id() -> &'static str {
                "test.rejoin_request"
            }

            fn class() -> MessageClass {
                MessageClass::Recovery
            }
        }
        #[derive(Debug, Hbor, PartialEq)]
        struct RejoinResp(u32);
        impl NetworkMessage for RejoinResp {
            fn message_type_id() -> &'static str {
                "test.rejoin_response"
            }

            fn class() -> MessageClass {
                MessageClass::Recovery
            }
        }
        impl Request for RejoinReq {
            type Response = RejoinResp;
        }

        let registry = HandlerRegistry::default();
        let shard_a = ShardId::leaf(1, 0);
        let shard_b = ShardId::leaf(1, 1);
        registry.register_request(shard_a, |req: RejoinReq| RejoinResp(req.0));
        registry.register_request(shard_b, |req: RejoinReq| RejoinResp(req.0 + 100));

        registry.unregister_requests_for_shard(shard_a);
        assert!(
            registry
                .get_request("test.rejoin_request", shard_a)
                .is_none()
        );
        assert!(
            registry
                .local_dispatch_request(shard_a, RejoinReq(1))
                .is_none()
        );
        // Shard B's handler survives.
        assert_eq!(
            registry.local_dispatch_request(shard_b, RejoinReq(1)),
            Some(RejoinResp(101))
        );

        // Re-join: registration succeeds again and serves.
        registry.register_request(shard_a, |req: RejoinReq| RejoinResp(req.0 + 1));
        assert_eq!(
            registry.local_dispatch_request(shard_a, RejoinReq(1)),
            Some(RejoinResp(2))
        );
    }

    #[test]
    #[should_panic(expected = "duplicate gossip handler registration")]
    fn test_double_registration_panics() {
        use hyperscale_hbor::Hbor;
        use hyperscale_types::NetworkMessage;

        #[derive(Debug, Clone, Hbor)]
        struct TestMsg(u32);
        impl NetworkMessage for TestMsg {
            fn message_type_id() -> &'static str {
                "test"
            }

            fn class() -> MessageClass {
                MessageClass::Recovery
            }
        }
        impl GossipMessage for TestMsg {
            const SCOPE: GossipScope = GossipScope::Shard;
        }

        let registry = HandlerRegistry::default();
        registry.register_gossip(|_: TestMsg, _shard: ShardId| -> Verdict { Verdict::Accept });
        registry.register_gossip(|_: TestMsg, _shard: ShardId| -> Verdict { Verdict::Accept });
    }

    /// A `Verifiable::Verified` value handed to [`HandlerRegistry::local_dispatch_gossip`]
    /// must arrive at the handler still in the `Verified` variant. This is the
    /// in-process fast path: colocated vnodes share a trust domain, so a
    /// producer that verified a payload before publishing must not have its
    /// verification thrown away by the dispatch boundary.
    #[test]
    fn local_dispatch_gossip_preserves_verified_marker() {
        use std::sync::Mutex;

        use hyperscale_hbor::Hbor;
        use hyperscale_types::{NetworkMessage, Verifiable, Verified};

        #[derive(Debug, Clone, Hbor)]
        struct VTestMsg {
            payload: Verifiable<u32>,
        }

        impl NetworkMessage for VTestMsg {
            fn message_type_id() -> &'static str {
                "test.local_dispatch_verified"
            }

            fn class() -> MessageClass {
                MessageClass::Recovery
            }
        }
        impl GossipMessage for VTestMsg {
            const SCOPE: GossipScope = GossipScope::Shard;
        }

        let hosted: BTreeSet<ShardId> = std::iter::once(ShardId::leaf(1, 0)).collect();
        let registry = HandlerRegistry::new(hosted);

        let observed: Arc<Mutex<Option<Verifiable<u32>>>> = Arc::new(Mutex::new(None));
        let observed_clone = Arc::clone(&observed);

        registry.register_gossip(move |msg: VTestMsg, _shard: ShardId| -> Verdict {
            *observed_clone.lock().unwrap() = Some(msg.payload);
            Verdict::Accept
        });

        let verified_msg = VTestMsg {
            payload: Verified::new_unchecked_for_test(42u32).into(),
        };
        let verdict = registry.local_dispatch_gossip(&verified_msg, Some(ShardId::leaf(1, 0)));
        assert_eq!(verdict, Some(Verdict::Accept));

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

    /// A registered host-level gossip handler receives a Global, source-`None`
    /// message even on a host with no hosted shards — on both the wire path
    /// (`get_host_gossip`) and the local-dispatch path — while a
    /// shard-scoped publish never reaches it.
    #[test]
    fn host_gossip_receives_source_none_global_gossip() {
        use hyperscale_hbor::{Hbor, to_vec as hbor_to_vec};
        use hyperscale_types::NetworkMessage;

        #[derive(Debug, Clone, Hbor)]
        struct GlobalMsg(u32);
        impl NetworkMessage for GlobalMsg {
            fn message_type_id() -> &'static str {
                "test.host_gossip"
            }

            fn class() -> MessageClass {
                MessageClass::Recovery
            }
        }
        impl GossipMessage for GlobalMsg {
            const SCOPE: GossipScope = GossipScope::Global;
        }

        // No hosted shards: the per-shard Global fan is empty.
        let registry = HandlerRegistry::new(BTreeSet::new());
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = Arc::clone(&hits);
        registry.register_host_gossip_handler(move |_msg: GlobalMsg| {
            hits_clone.fetch_add(1, Ordering::SeqCst);
        });

        // Wire path.
        let host_handler = registry.get_host_gossip("test.host_gossip").unwrap();
        host_handler(hbor_to_vec(&GlobalMsg(1)).unwrap());
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // Local-dispatch path (global publish carries `shard == None`).
        let _ = registry.local_dispatch_gossip(&GlobalMsg(2), None);
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        // A shard-scoped publish does not reach the host-level handler.
        let _ = registry.local_dispatch_gossip(&GlobalMsg(3), Some(ShardId::leaf(1, 0)));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[test]
    #[should_panic(expected = "duplicate host gossip handler registration")]
    fn host_gossip_double_registration_panics() {
        use hyperscale_hbor::Hbor;
        use hyperscale_types::NetworkMessage;

        #[derive(Debug, Clone, Hbor)]
        struct GlobalMsg(u32);
        impl NetworkMessage for GlobalMsg {
            fn message_type_id() -> &'static str {
                "test.host_gossip_dup"
            }

            fn class() -> MessageClass {
                MessageClass::Recovery
            }
        }
        impl GossipMessage for GlobalMsg {
            const SCOPE: GossipScope = GossipScope::Global;
        }

        let registry = HandlerRegistry::default();
        registry.register_host_gossip_handler(|_: GlobalMsg| {});
        registry.register_host_gossip_handler(|_: GlobalMsg| {});
    }
}
