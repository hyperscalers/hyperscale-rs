//! Finalized beacon-block gossip.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{BeaconBlock, MessageClass, NetworkMessage};

/// Broadcasts a finalized [`BeaconBlock`] globally for light-client
/// pickup, cross-shard verification, and committee handover.
///
/// The block is self-authenticating via the [`SpcCert`](crate::SpcCert)
/// in [`BeaconBlock::cert`] — verifiers check it under the epoch's
/// committee (resolved from the previous epoch's `BeaconState`). No
/// outer sender signature is needed; multiple publishers broadcasting
/// the same canonical bytes collapse via gossipsub's bytes-id dedup.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconBlockGossip {
    /// The finalized beacon block.
    pub block: Arc<BeaconBlock>,
}

impl BeaconBlockGossip {
    /// Wrap a [`BeaconBlock`] for gossip broadcast.
    #[must_use]
    pub fn new(block: impl Into<Arc<BeaconBlock>>) -> Self {
        Self {
            block: block.into(),
        }
    }

    /// Get the inner block.
    #[must_use]
    pub fn block(&self) -> &BeaconBlock {
        &self.block
    }

    /// Consume and return the inner block.
    #[must_use]
    pub fn into_block(self) -> Arc<BeaconBlock> {
        self.block
    }
}

impl NetworkMessage for BeaconBlockGossip {
    fn message_type_id() -> &'static str {
        "beacon.block"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl GossipMessage for BeaconBlockGossip {
    const SCOPE: TopicScope = TopicScope::Global;
}

#[cfg(test)]
mod tests {
    use sbor::prelude::*;

    use super::*;
    use crate::GenesisConfigHash;

    #[test]
    fn sbor_round_trip() {
        let block = BeaconBlock::genesis(GenesisConfigHash::ZERO);
        let g = BeaconBlockGossip::new(block);
        let bytes = basic_encode(&g).unwrap();
        let decoded: BeaconBlockGossip = basic_decode(&bytes).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn class_is_cross_shard_progress() {
        assert_eq!(BeaconBlockGossip::class(), MessageClass::CrossShardProgress);
    }

    #[test]
    fn scope_is_global() {
        assert!(matches!(BeaconBlockGossip::SCOPE, TopicScope::Global));
    }
}
