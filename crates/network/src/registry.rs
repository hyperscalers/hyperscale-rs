//! Per-message-type handler registry.
//!
//! Stores gossip and request handlers keyed by `message_type_id`.
//! Both production and simulation network backends share a registry
//! instance between the Network impl and the transport layer.
//!
//! Handlers are stored as type-erased closures. The typed
//! `GossipHandler<M>` / `RequestHandler<R>` wrappers live in each
//! `Network` impl, which wraps them before storing here.
//!
//! All registrations happen at init (before any messages arrive), so
//! the read-heavy RwLock pattern is ideal.

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

    /// Register a gossip handler for a message type.
    ///
    /// Overwrites any previously registered handler for the same type.
    pub fn register_gossip(&self, message_type_id: &'static str, handler: Arc<RawGossipHandler>) {
        self.gossip
            .write()
            .unwrap()
            .insert(message_type_id, handler);
    }

    /// Register a request handler for a message type.
    ///
    /// Overwrites any previously registered handler for the same type.
    pub fn register_request(&self, message_type_id: &'static str, handler: Arc<RawRequestHandler>) {
        self.request
            .write()
            .unwrap()
            .insert(message_type_id, handler);
    }

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
        let registry = HandlerRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let handler: Arc<RawGossipHandler> = Arc::new(move |_payload: Vec<u8>| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        registry.register_gossip("block.vote", handler);

        let retrieved = registry.get_gossip("block.vote").unwrap();
        retrieved(vec![]);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        assert!(registry.get_gossip("unknown.type").is_none());
    }

    #[test]
    fn test_register_and_lookup_request() {
        let registry = HandlerRegistry::new();
        let handler: Arc<RawRequestHandler> =
            Arc::new(|payload: &[u8]| -> Vec<u8> { payload.to_vec() });

        registry.register_request("block.request", handler);

        let retrieved = registry.get_request("block.request").unwrap();
        let response = retrieved(b"hello");
        assert_eq!(response, b"hello");

        assert!(registry.get_request("unknown.request").is_none());
    }

    #[test]
    fn test_overwrite_handler() {
        let registry = HandlerRegistry::new();
        let counter1 = Arc::new(AtomicUsize::new(0));
        let counter2 = Arc::new(AtomicUsize::new(0));

        let c1 = counter1.clone();
        registry.register_gossip(
            "test",
            Arc::new(move |_: Vec<u8>| {
                c1.fetch_add(1, Ordering::SeqCst);
            }),
        );
        let c2 = counter2.clone();
        registry.register_gossip(
            "test",
            Arc::new(move |_: Vec<u8>| {
                c2.fetch_add(1, Ordering::SeqCst);
            }),
        );

        registry.get_gossip("test").unwrap()(vec![]);

        // Second handler should have won
        assert_eq!(counter1.load(Ordering::SeqCst), 0);
        assert_eq!(counter2.load(Ordering::SeqCst), 1);
    }
}
