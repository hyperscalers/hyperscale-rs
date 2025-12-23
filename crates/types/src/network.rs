//! Network message traits.
//!
//! These traits mark types as network messages for serialization and routing.
//! They replace the dependency on `hyperscale-network`.

use sbor::prelude::{BasicDecode, BasicEncode};

/// Marker trait for network messages.
///
/// All messages sent over the network must implement this trait.
pub trait NetworkMessage: Send + Sync + Sized + BasicEncode + BasicDecode {
    /// Unique message type identifier for routing.
    fn message_type_id() -> &'static str
    where
        Self: Sized;

    /// Get the gossipsub topic for this message type.
    fn topic() -> String
    where
        Self: Sized,
    {
        format!("hyperscale/{}/1.0.0", Self::message_type_id())
    }
}

/// Marker trait for messages that are shard-specific.
pub trait ShardMessage: NetworkMessage {}

/// Marker trait for request messages that expect a response.
pub trait Request: NetworkMessage {
    /// The response type for this request.
    type Response: NetworkMessage;
}
