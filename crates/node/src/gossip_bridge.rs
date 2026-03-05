//! Per-type gossip bridge to the IoLoop event channel.
//!
//! Each message type gets its own [`TypedGossipBridge`] that captures the
//! `message_type` string and forwards raw payloads as
//! `NodeInput::GossipReceived` events for the IoLoop's existing dispatch.
//!
//! Registered via `Network::register_gossip_handler` (once per type)
//! during IoLoop initialization.

use hyperscale_core::NodeInput;
use hyperscale_network::GossipHandler;

/// Gossip handler for a single message type that forwards to the IoLoop event channel.
///
/// Each instance captures its message type, so the IoLoop can dispatch
/// the payload to the correct handler.
pub struct TypedGossipBridge {
    message_type: &'static str,
    tx: crossbeam::channel::Sender<NodeInput>,
}

impl TypedGossipBridge {
    pub fn new(message_type: &'static str, tx: crossbeam::channel::Sender<NodeInput>) -> Self {
        Self { message_type, tx }
    }
}

impl GossipHandler for TypedGossipBridge {
    fn on_message(&self, payload: Vec<u8>) {
        let _ = self.tx.send(NodeInput::GossipReceived {
            message_type: self.message_type,
            payload,
        });
    }
}
