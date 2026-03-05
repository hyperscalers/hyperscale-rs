//! Per-message-type handler registry.
//!
//! Stores gossip and request handlers keyed by `message_type_id`.
//! Both production and simulation network backends share a registry
//! instance between the Network impl and the transport layer.
//!
//! All registrations happen at init (before any messages arrive), so
//! the read-heavy RwLock pattern is ideal.

use crate::traits::{GossipHandler, RequestHandler};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Registry of per-message-type handlers.
///
/// Shared between the `Network` impl (which registers handlers) and
/// the transport layer (which dispatches incoming messages).
pub struct HandlerRegistry {
    gossip: RwLock<HashMap<&'static str, Arc<dyn GossipHandler>>>,
    request: RwLock<HashMap<&'static str, Arc<dyn RequestHandler>>>,
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
    pub fn register_gossip(&self, message_type_id: &'static str, handler: Arc<dyn GossipHandler>) {
        self.gossip
            .write()
            .unwrap()
            .insert(message_type_id, handler);
    }

    /// Register a request handler for a message type.
    ///
    /// Overwrites any previously registered handler for the same type.
    pub fn register_request(
        &self,
        message_type_id: &'static str,
        handler: Arc<dyn RequestHandler>,
    ) {
        self.request
            .write()
            .unwrap()
            .insert(message_type_id, handler);
    }

    /// Look up the gossip handler for a message type.
    pub fn get_gossip(&self, message_type_id: &str) -> Option<Arc<dyn GossipHandler>> {
        self.gossip.read().unwrap().get(message_type_id).cloned()
    }

    /// Look up the request handler for a message type.
    pub fn get_request(&self, message_type_id: &str) -> Option<Arc<dyn RequestHandler>> {
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

    struct CountingGossipHandler(Arc<AtomicUsize>);
    impl GossipHandler for CountingGossipHandler {
        fn on_message(&self, _payload: Vec<u8>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct EchoRequestHandler;
    impl RequestHandler for EchoRequestHandler {
        fn handle_request(&self, payload: &[u8]) -> Vec<u8> {
            payload.to_vec()
        }
    }

    #[test]
    fn test_register_and_lookup_gossip() {
        let registry = HandlerRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(CountingGossipHandler(counter.clone()));

        registry.register_gossip("block.vote", handler);

        let retrieved = registry.get_gossip("block.vote").unwrap();
        retrieved.on_message(vec![]);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        assert!(registry.get_gossip("unknown.type").is_none());
    }

    #[test]
    fn test_register_and_lookup_request() {
        let registry = HandlerRegistry::new();
        let handler = Arc::new(EchoRequestHandler);

        registry.register_request("block.request", handler);

        let retrieved = registry.get_request("block.request").unwrap();
        let response = retrieved.handle_request(b"hello");
        assert_eq!(response, b"hello");

        assert!(registry.get_request("unknown.request").is_none());
    }

    #[test]
    fn test_overwrite_handler() {
        let registry = HandlerRegistry::new();
        let counter1 = Arc::new(AtomicUsize::new(0));
        let counter2 = Arc::new(AtomicUsize::new(0));

        registry.register_gossip("test", Arc::new(CountingGossipHandler(counter1.clone())));
        registry.register_gossip("test", Arc::new(CountingGossipHandler(counter2.clone())));

        registry.get_gossip("test").unwrap().on_message(vec![]);

        // Second handler should have won
        assert_eq!(counter1.load(Ordering::SeqCst), 0);
        assert_eq!(counter2.load(Ordering::SeqCst), 1);
    }
}
