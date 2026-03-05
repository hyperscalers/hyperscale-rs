//! Bridges network gossip to the IoLoop event channel.
//!
//! Both production and simulation register an instance of [`ChannelGossipHandler`].
//! The handler wraps a crossbeam sender and converts gossip into
//! `NodeInput::GossipReceived` events for the IoLoop.

use hyperscale_core::NodeInput;
use hyperscale_network::GossipHandler;

/// Gossip handler that forwards messages to the IoLoop event channel.
pub struct ChannelGossipHandler {
    tx: crossbeam::channel::Sender<NodeInput>,
}

impl ChannelGossipHandler {
    pub fn new(tx: crossbeam::channel::Sender<NodeInput>) -> Self {
        Self { tx }
    }
}

impl GossipHandler for ChannelGossipHandler {
    fn on_gossip(&self, message_type: &'static str, payload: Vec<u8>) {
        let _ = self.tx.send(NodeInput::GossipReceived {
            message_type,
            payload,
        });
    }
}
