//! Finalized beacon-block gossip.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{CertifiedBeaconBlock, MessageClass, NetworkMessage, Verifiable};

/// Broadcasts a finalized [`CertifiedBeaconBlock`] globally for
/// light-client pickup, cross-shard verification, and committee
/// handover.
///
/// The block is self-authenticating via the [`BeaconCert`](crate::BeaconCert)
/// in [`CertifiedBeaconBlock::cert`] — verifiers check it under the
/// epoch's committee (resolved from the previous epoch's `BeaconState`).
/// No outer sender signature is needed; multiple publishers broadcasting
/// the same canonical bytes collapse via gossipsub's bytes-id dedup.
///
/// Wire decode lands the wrapper as `Verifiable::Unverified`;
/// locally-dispatched sends from a colocated commit path preserve
/// `Verifiable::Verified`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconBlockGossip {
    /// The finalized beacon block paired with its authenticating cert.
    pub block: Arc<Verifiable<CertifiedBeaconBlock>>,
}

impl BeaconBlockGossip {
    /// Wrap a [`CertifiedBeaconBlock`] for gossip broadcast. Accepts
    /// a raw block or a `Verified<CertifiedBeaconBlock>` — the wrapper
    /// preserves the marker.
    #[must_use]
    pub fn new(block: impl Into<Arc<Verifiable<CertifiedBeaconBlock>>>) -> Self {
        Self {
            block: block.into(),
        }
    }

    /// Get the inner block (raw view, regardless of verification
    /// state).
    #[must_use]
    pub fn block(&self) -> &CertifiedBeaconBlock {
        self.block.as_unverified()
    }

    /// Consume and return the inner block, preserving the
    /// verification marker.
    #[must_use]
    pub fn into_block(self) -> Arc<Verifiable<CertifiedBeaconBlock>> {
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
        let block = CertifiedBeaconBlock::genesis(GenesisConfigHash::ZERO);
        let g = BeaconBlockGossip::new(Arc::new(Verifiable::from(block)));
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
