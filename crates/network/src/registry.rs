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
//! the read-heavy RwLock pattern is ideal.

use crate::traits::{GossipHandler, RequestHandler};
use hyperscale_types::{NetworkMessage, Request};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Type-erased gossip handler: receives decompressed SBOR bytes.
pub type RawGossipHandler = dyn Fn(Vec<u8>) + Send + Sync;

/// Type-erased request handler: receives SBOR request bytes, returns SBOR response bytes.
pub type RawRequestHandler = dyn Fn(&[u8]) -> Vec<u8> + Send + Sync;

/// Registry of per-message-type handlers.
///
/// Shared between the `Network` impl (which registers handlers) and
/// the transport layer (which dispatches incoming messages).
pub struct HandlerRegistry {
    gossip: RwLock<HashMap<&'static str, Arc<RawGossipHandler>>>,
    request: RwLock<HashMap<&'static str, Arc<RawRequestHandler>>>,
}

impl HandlerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            gossip: RwLock::new(HashMap::new()),
            request: RwLock::new(HashMap::new()),
        }
    }

    // ── Typed registration (used by Network impls) ──

    /// Register a typed gossip handler for a message type.
    ///
    /// Wraps the handler in a closure that SBOR-decodes the payload before
    /// calling the handler. Decode errors are logged and the message is dropped.
    pub fn register_gossip<M: NetworkMessage>(&self, handler: impl GossipHandler<M>) {
        let raw: Arc<RawGossipHandler> = Arc::new(
            move |payload: Vec<u8>| match sbor::basic_decode::<M>(&payload) {
                Ok(msg) => handler.on_message(msg),
                Err(e) => {
                    tracing::warn!(
                        message_type = M::message_type_id(),
                        error = ?e,
                        "Failed to SBOR-decode gossip message — dropping"
                    );
                }
            },
        );
        self.gossip
            .write()
            .unwrap()
            .insert(M::message_type_id(), raw);
    }

    /// Register a typed request handler for a message type.
    ///
    /// Wraps the handler in a closure that SBOR-decodes the request,
    /// calls the handler, and SBOR-encodes the response.
    pub fn register_request<R: Request>(&self, handler: impl RequestHandler<R>) {
        let raw: Arc<RawRequestHandler> = Arc::new(move |payload: &[u8]| -> Vec<u8> {
            let req = match sbor::basic_decode::<R>(payload) {
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
            let response = handler.handle_request(req);
            match sbor::basic_encode(&response) {
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

        self.request
            .write()
            .unwrap()
            .insert(R::message_type_id(), raw);
    }

    // ── Raw registration (used by infrastructure tests) ──

    /// Register a raw gossip handler by type_id string.
    ///
    /// Prefer [`register_gossip`](Self::register_gossip) for production code.
    /// This is useful for infrastructure tests that work with raw bytes.
    pub fn register_raw_gossip(&self, type_id: &'static str, handler: Arc<RawGossipHandler>) {
        self.gossip.write().unwrap().insert(type_id, handler);
    }

    /// Register a raw request handler by type_id string.
    ///
    /// Prefer [`register_request`](Self::register_request) for production code.
    /// This is useful for infrastructure tests that work with raw bytes.
    pub fn register_raw_request(&self, type_id: &'static str, handler: Arc<RawRequestHandler>) {
        self.request.write().unwrap().insert(type_id, handler);
    }

    // ── Transport-layer dispatch (used by inbound router / sim harness) ──

    /// Look up the gossip handler for a message type.
    pub fn get_gossip(&self, message_type_id: &str) -> Option<Arc<RawGossipHandler>> {
        self.gossip.read().unwrap().get(message_type_id).cloned()
    }

    /// Look up the request handler for a message type.
    pub fn get_request(&self, message_type_id: &str) -> Option<Arc<RawRequestHandler>> {
        self.request.read().unwrap().get(message_type_id).cloned()
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_register_and_lookup_gossip() {
        use hyperscale_types::NetworkMessage;
        use sbor::{Decode, Encode};

        #[derive(Debug, Encode, Decode)]
        struct TestMsg(u32);
        impl NetworkMessage for TestMsg {
            fn message_type_id() -> &'static str {
                "test.gossip"
            }
        }

        let registry = HandlerRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        registry.register_gossip(move |_msg: TestMsg| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let handler = registry.get_gossip("test.gossip").unwrap();
        let encoded = sbor::basic_encode(&TestMsg(42)).unwrap();
        handler(encoded);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        assert!(registry.get_gossip("unknown.type").is_none());
    }

    #[test]
    fn test_register_and_lookup_request() {
        use hyperscale_types::{NetworkMessage, Request};
        use sbor::{Decode, Encode};

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

        registry.register_request(|req: TestReq| TestResp(req.0 * 2));

        let handler = registry.get_request("test.request").unwrap();
        let req_bytes = sbor::basic_encode(&TestReq(21)).unwrap();
        let response_bytes = handler(&req_bytes);
        let response: TestResp = sbor::basic_decode(&response_bytes).unwrap();
        assert_eq!(response, TestResp(42));

        assert!(registry.get_request("unknown.request").is_none());
    }

    #[test]
    fn test_overwrite_handler() {
        use hyperscale_types::NetworkMessage;
        use sbor::{Decode, Encode};

        #[derive(Debug, Encode, Decode)]
        struct TestMsg(u32);
        impl NetworkMessage for TestMsg {
            fn message_type_id() -> &'static str {
                "test"
            }
        }

        let registry = HandlerRegistry::new();
        let counter1 = Arc::new(AtomicUsize::new(0));
        let counter2 = Arc::new(AtomicUsize::new(0));

        let c1 = counter1.clone();
        registry.register_gossip(move |_: TestMsg| {
            c1.fetch_add(1, Ordering::SeqCst);
        });
        let c2 = counter2.clone();
        registry.register_gossip(move |_: TestMsg| {
            c2.fetch_add(1, Ordering::SeqCst);
        });

        let handler = registry.get_gossip("test").unwrap();
        let encoded = sbor::basic_encode(&TestMsg(1)).unwrap();
        handler(encoded);

        // Second handler should have won
        assert_eq!(counter1.load(Ordering::SeqCst), 0);
        assert_eq!(counter2.load(Ordering::SeqCst), 1);
    }
}
