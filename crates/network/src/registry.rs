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
//! the read-heavy `RwLock` pattern is ideal.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, PoisonError, RwLock};

use hyperscale_types::{NetworkMessage, Request, ShardGroupId};
use sbor::{basic_decode, basic_encode};

use crate::traits::{GossipHandler, GossipVerdict, NotificationHandler, RequestHandler};

/// Type-erased gossip handler: receives decompressed SBOR bytes, returns verdict.
pub type RawGossipHandler = dyn Fn(Vec<u8>) -> GossipVerdict + Send + Sync;

/// Type-erased notification handler: receives decompressed SBOR bytes, no return value.
pub type RawNotificationHandler = dyn Fn(Vec<u8>) + Send + Sync;

/// Type-erased request handler: receives SBOR request bytes, returns SBOR response bytes.
pub type RawRequestHandler = dyn Fn(&[u8]) -> Vec<u8> + Send + Sync;

/// Dispatch a typed gossip message into its handler without SBOR
/// encode/decode. Used by network backends to deliver locally-published
/// messages to in-process subscribers.
pub trait LocalGossipDispatcher: Send + Sync {
    /// Dispatch `msg` (downcast from `&dyn Any` to the registered `M`)
    /// to the typed handler. The handler consumes `M`, so the dispatcher
    /// clones internally.
    fn dispatch(&self, msg: &dyn Any) -> GossipVerdict;
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

struct TypedGossipDispatcher<M, H> {
    handler: Arc<H>,
    _phantom: PhantomData<fn() -> M>,
}

impl<M, H> LocalGossipDispatcher for TypedGossipDispatcher<M, H>
where
    M: NetworkMessage + Clone + 'static,
    H: GossipHandler<M>,
{
    fn dispatch(&self, msg: &dyn Any) -> GossipVerdict {
        let typed = msg
            .downcast_ref::<M>()
            .expect("local gossip dispatch type mismatch");
        self.handler.on_message(typed.clone())
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
/// because their closures dispatch into the state machine, which
/// internally fans out across hosted shards.
pub struct HandlerRegistry {
    gossip: RwLock<HashMap<&'static str, Arc<RawGossipHandler>>>,
    request: RwLock<HashMap<(&'static str, ShardGroupId), Arc<RawRequestHandler>>>,
    notification: RwLock<HashMap<&'static str, Arc<RawNotificationHandler>>>,
    /// Typed gossip dispatchers keyed by message `TypeId` for
    /// zero-encode local delivery to colocated subscribers.
    local_gossip: RwLock<HashMap<TypeId, Arc<dyn LocalGossipDispatcher>>>,
    /// Typed notification dispatchers (same role as `local_gossip`).
    local_notification: RwLock<HashMap<TypeId, Arc<dyn LocalNotificationDispatcher>>>,
    /// Typed request dispatchers keyed by `(TypeId, ShardGroupId)` for
    /// in-process request serving. Used when a host carries a vnode in
    /// the target shard — bypasses libp2p and preserves `Arc`-shared
    /// payloads on the response.
    local_request: RwLock<HashMap<(TypeId, ShardGroupId), Arc<dyn LocalRequestDispatcher>>>,
}

impl HandlerRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            gossip: RwLock::new(HashMap::new()),
            request: RwLock::new(HashMap::new()),
            notification: RwLock::new(HashMap::new()),
            local_gossip: RwLock::new(HashMap::new()),
            local_notification: RwLock::new(HashMap::new()),
            local_request: RwLock::new(HashMap::new()),
        }
    }

    // ── Typed registration (used by Network impls) ──

    /// Register a typed gossip handler for a message type.
    ///
    /// Wraps the handler in a closure that SBOR-decodes the payload before
    /// calling the handler. Decode errors are logged and the message is dropped.
    ///
    /// # Panics
    ///
    /// Panics if a handler is already registered for this message type. All
    /// registrations happen once at init; a duplicate is a programmer error.
    pub fn register_gossip<M>(&self, handler: impl GossipHandler<M>)
    where
        M: NetworkMessage + Clone + 'static,
    {
        let handler = Arc::new(handler);

        let bytes_handler = Arc::clone(&handler);
        let raw: Arc<RawGossipHandler> =
            Arc::new(move |payload: Vec<u8>| match basic_decode::<M>(&payload) {
                Ok(msg) => bytes_handler.on_message(msg),
                Err(e) => {
                    tracing::warn!(
                        message_type = M::message_type_id(),
                        error = ?e,
                        "Failed to SBOR-decode gossip message — rejecting"
                    );
                    GossipVerdict::Reject
                }
            });
        let prior = self
            .gossip
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(M::message_type_id(), raw);
        assert!(
            prior.is_none(),
            "duplicate gossip handler registration for {}",
            M::message_type_id(),
        );

        let typed: Arc<dyn LocalGossipDispatcher> = Arc::new(TypedGossipDispatcher::<M, _> {
            handler,
            _phantom: PhantomData,
        });
        self.local_gossip
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(TypeId::of::<M>(), typed);
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

        let prior = self
            .request
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((R::message_type_id(), shard), raw);
        assert!(
            prior.is_none(),
            "duplicate request handler registration for ({}, {shard:?})",
            R::message_type_id(),
        );

        let typed: Arc<dyn LocalRequestDispatcher> = Arc::new(TypedRequestDispatcher::<R, _> {
            handler,
            _phantom: PhantomData,
        });
        self.local_request
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((TypeId::of::<R>(), shard), typed);
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
        let prior = self
            .notification
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(M::message_type_id(), raw);
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
        self.local_notification
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(TypeId::of::<M>(), typed);
    }

    // ── Raw registration (used by infrastructure tests) ──

    /// Register a raw gossip handler by `type_id` string.
    ///
    /// Prefer [`register_gossip`](Self::register_gossip) for production code.
    /// This is useful for infrastructure tests that work with raw bytes.
    pub fn register_raw_gossip(&self, type_id: &'static str, handler: Arc<RawGossipHandler>) {
        self.gossip
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(type_id, handler);
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
        self.request
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((type_id, shard), handler);
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
        self.notification
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(type_id, handler);
    }

    // ── Transport-layer dispatch (used by inbound router / sim harness) ──

    /// Look up the gossip handler for a message type.
    #[must_use]
    pub fn get_gossip(&self, message_type_id: &str) -> Option<Arc<RawGossipHandler>> {
        self.gossip
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(message_type_id)
            .cloned()
    }

    /// Look up the request handler for `(type_id, shard)`.
    #[must_use]
    pub fn get_request(
        &self,
        message_type_id: &str,
        shard: ShardGroupId,
    ) -> Option<Arc<RawRequestHandler>> {
        self.request
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(message_type_id, shard))
            .cloned()
    }

    /// Look up the notification handler for a message type.
    #[must_use]
    pub fn get_notification(&self, message_type_id: &str) -> Option<Arc<RawNotificationHandler>> {
        self.notification
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(message_type_id)
            .cloned()
    }

    /// Dispatch a typed gossip message into its in-process handler,
    /// skipping SBOR encode/decode. Returns `None` if no handler for
    /// `M` is registered. Network backends use this to short-circuit
    /// local delivery for messages they publish.
    #[must_use]
    pub fn local_dispatch_gossip<M>(&self, msg: &M) -> Option<GossipVerdict>
    where
        M: NetworkMessage + 'static,
    {
        self.local_gossip
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&TypeId::of::<M>())
            .map(|d| d.dispatch(msg as &dyn Any))
    }

    /// Dispatch a typed notification message into its in-process handler,
    /// skipping SBOR encode/decode. Returns `false` if no handler for
    /// `M` is registered.
    pub fn local_dispatch_notification<M>(&self, msg: &M) -> bool
    where
        M: NetworkMessage + 'static,
    {
        self.local_notification
            .read()
            .unwrap_or_else(PoisonError::into_inner)
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
            .read()
            .unwrap_or_else(PoisonError::into_inner)
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
        Self::new()
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

        let registry = HandlerRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        registry.register_gossip(move |_msg: TestMsg| -> GossipVerdict {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            GossipVerdict::Accept
        });

        let handler = registry.get_gossip("test.gossip").unwrap();
        let encoded = basic_encode(&TestMsg(42)).unwrap();
        let verdict = handler(encoded);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(verdict, GossipVerdict::Accept);

        // SBOR decode failure should return Reject.
        let verdict = handler(vec![0xFF, 0xFE]);
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

        let registry = HandlerRegistry::new();
        let shard = ShardGroupId::new(0);

        registry.register_request(shard, |req: TestReq| TestResp(req.0 * 2));

        let handler = registry.get_request("test.request", shard).unwrap();
        let req_bytes = basic_encode(&TestReq(21)).unwrap();
        let response_bytes = handler(&req_bytes);
        let response: TestResp = basic_decode(&response_bytes).unwrap();
        assert_eq!(response, TestResp(42));

        assert!(registry.get_request("unknown.request", shard).is_none());
        assert!(
            registry
                .get_request("test.request", ShardGroupId::new(1))
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

        let registry = HandlerRegistry::new();
        registry.register_gossip(|_: TestMsg| -> GossipVerdict { GossipVerdict::Accept });
        registry.register_gossip(|_: TestMsg| -> GossipVerdict { GossipVerdict::Accept });
    }
}
