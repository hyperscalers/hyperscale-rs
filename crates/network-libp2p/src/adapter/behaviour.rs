//! libp2p network behaviour definition.

use libp2p::{gossipsub, identify, kad, swarm::NetworkBehaviour, StreamProtocol};
use libp2p_stream as stream;

/// Protocol identifier for raw stream requests.
pub const STREAM_PROTOCOL: StreamProtocol = StreamProtocol::new("/hyperscale/req/2.0.0");

/// libp2p network behaviour combining gossipsub, Kademlia, and raw streams.
#[derive(NetworkBehaviour)]
pub(super) struct Behaviour {
    /// Gossipsub for efficient broadcast.
    pub(super) gossipsub: gossipsub::Behaviour,

    /// Kademlia DHT for peer discovery.
    pub(super) kademlia: kad::Behaviour<kad::store::MemoryStore>,

    /// Raw streams for request/response (replaces request_response).
    /// RequestManager owns all timeout logic; this is just a "dumb pipe".
    pub(super) stream: stream::Behaviour,

    /// Identify protocol for peer versioning.
    pub(super) identify: identify::Behaviour,

    /// Connection limits to prevent storms.
    pub(super) limits: libp2p::connection_limits::Behaviour,
}
