//! Type-erased handler registry for network message dispatch.
//!
//! Shared utility for both `network-libp2p` and `network-memory` implementations
//! of the `Network` trait. Stores typed handlers keyed by message type ID and
//! dispatches incoming bytes to the correct handler after decoding.

use hyperscale_types::{NetworkMessage, ValidatorId};
use std::collections::HashMap;
use std::sync::RwLock;

/// Type-erased handler that decodes from bytes and calls the typed handler.
type RawHandler = Box<dyn Fn(ValidatorId, &[u8]) + Send + Sync>;

/// Registry of typed message handlers, keyed by message type ID.
///
/// Thread-safe via `RwLock` — registrations are rare, dispatches are frequent.
pub struct HandlerRegistry {
    handlers: RwLock<HashMap<&'static str, Vec<RawHandler>>>,
}

impl HandlerRegistry {
    /// Create a new empty handler registry.
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a typed handler for a message type.
    ///
    /// The handler will be called when `dispatch` is invoked with the matching
    /// `type_id`. The raw bytes are decoded into `M` before calling the handler.
    /// Decode failures are silently dropped (logged at trace level in production).
    pub fn register<M: NetworkMessage + 'static>(
        &self,
        handler: Box<dyn Fn(ValidatorId, M) + Send + Sync>,
    ) {
        let erased: RawHandler = Box::new(move |sender, bytes| {
            if let Ok(msg) = sbor::basic_decode::<M>(bytes) {
                handler(sender, msg);
            }
        });
        self.handlers
            .write()
            .expect("handler registry lock poisoned")
            .entry(M::message_type_id())
            .or_default()
            .push(erased);
    }

    /// Dispatch raw bytes to all registered handlers for the given type ID.
    ///
    /// Called from the network's decode/delivery thread with the sender's identity,
    /// the message type ID (from the wire format), and the raw SBOR-encoded bytes.
    pub fn dispatch(&self, sender: ValidatorId, type_id: &str, bytes: &[u8]) {
        let handlers = self
            .handlers
            .read()
            .expect("handler registry lock poisoned");
        if let Some(handlers) = handlers.get(type_id) {
            for handler in handlers {
                handler(sender, bytes);
            }
        }
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}
