//! libp2p network behaviour definition.

use hyperscale_types::ShardId;
use libp2p::StreamProtocol;
use libp2p::connection_limits::Behaviour as ConnectionLimitsBehaviour;
use libp2p::gossipsub::Behaviour as GossipsubBehaviour;
use libp2p::identify::Behaviour as IdentifyBehaviour;
use libp2p::kad::Behaviour as KadBehaviour;
use libp2p::kad::store::MemoryStore as KadMemoryStore;
use libp2p::swarm::NetworkBehaviour;
use libp2p_stream::Behaviour as StreamBehaviour;

/// Stream protocol identifier for request/response on `shard`.
///
/// One protocol per hosted shard: a multi-shard host registers one accept
/// loop per shard, and outbound requests pick the protocol corresponding
/// to the routing shard threaded through from `Network::request(shard,
/// ...)`. The protocol identifier is the routing signal — bodies do not
/// carry the shard.
#[must_use]
pub fn request_protocol(shard: ShardId) -> StreamProtocol {
    StreamProtocol::try_from_owned(format!("/hyperscale/request/shard-{}/1.0.0", shard.inner()))
        .expect("static prefix + decimal shard id is always a valid protocol string")
}

/// Protocol identifier for fire-and-forget notification streams.
///
/// Single protocol shared across hosted shards — notifications carry a
/// recipient `ValidatorId` already, and routing happens at the recipient
/// layer, not the wire.
pub const NOTIFY_PROTOCOL: StreamProtocol = StreamProtocol::new("/hyperscale/notify/1.0.0");

/// libp2p network behaviour combining gossipsub, Kademlia, and raw streams.
#[derive(NetworkBehaviour)]
pub(super) struct Behaviour {
    /// Gossipsub for efficient broadcast.
    pub(super) gossipsub: GossipsubBehaviour,

    /// Kademlia DHT for peer discovery.
    pub(super) kademlia: KadBehaviour<KadMemoryStore>,

    /// Raw streams for request/response (replaces `request_response`).
    /// `RequestManager` owns all timeout logic; this is just a "dumb pipe".
    pub(super) stream: StreamBehaviour,

    /// Identify protocol for peer versioning.
    pub(super) identify: IdentifyBehaviour,

    /// Connection limits to prevent storms.
    pub(super) limits: ConnectionLimitsBehaviour,
}
