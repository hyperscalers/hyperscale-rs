//! Message routing types for parallel simulation.

use hyperscale_types::ShardGroupId;

/// Where to send a message.
#[derive(Debug, Clone)]
pub enum Destination {
    /// Broadcast to all nodes in a shard.
    Shard(ShardGroupId),
    /// Broadcast to all nodes globally.
    Global,
}
