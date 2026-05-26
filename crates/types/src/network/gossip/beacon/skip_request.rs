//! Skip-request gossip — broadcast to the active validator pool.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{MessageClass, NetworkMessage, SkipRequest};

/// Broadcasts one active validator's signed skip attestation.
///
/// Gossiped across the full active validator pool; ⌈2M/3⌉ + 1 active
/// signers over the same `(anchor_hash, epoch_to_skip)` pair assemble
/// into a [`SkipEpochCert`](crate::SkipEpochCert) authenticating the
/// skip block.
///
/// The inner [`SkipRequest`] is self-authenticating — it carries the
/// signer id and a BLS signature. Each validator publishes a distinct
/// request with their own signature, so per-publisher bytes differ
/// and gossipsub's bytes-id dedup handles accidental re-publications
/// without an explicit content-key dedup.
///
/// `MessageClass::Consensus` — skip liveness is round-blocking: until
/// ⌈2M/3⌉ + 1 active signers' requests assemble, the chain doesn't
/// make progress.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SkipRequestGossip {
    /// The signed skip request.
    pub request: Arc<SkipRequest>,
}

impl SkipRequestGossip {
    /// Wrap a [`SkipRequest`] for gossip broadcast.
    #[must_use]
    pub fn new(request: impl Into<Arc<SkipRequest>>) -> Self {
        Self {
            request: request.into(),
        }
    }

    /// Get the inner request.
    #[must_use]
    pub fn request(&self) -> &SkipRequest {
        &self.request
    }

    /// Consume and return the inner request.
    #[must_use]
    pub fn into_request(self) -> Arc<SkipRequest> {
        self.request
    }
}

impl NetworkMessage for SkipRequestGossip {
    fn message_type_id() -> &'static str {
        "beacon.skip_request"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl GossipMessage for SkipRequestGossip {
    const SCOPE: TopicScope = TopicScope::Global;
}

#[cfg(test)]
mod tests {
    use sbor::prelude::*;

    use super::*;
    use crate::{BeaconBlockHash, Bls12381G2Signature, Epoch, Hash, ValidatorId};

    fn sample_request() -> SkipRequest {
        SkipRequest::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(7),
            ValidatorId::new(3),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    #[test]
    fn sbor_round_trip() {
        let g = SkipRequestGossip::new(sample_request());
        let bytes = basic_encode(&g).unwrap();
        let decoded: SkipRequestGossip = basic_decode(&bytes).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(SkipRequestGossip::class(), MessageClass::Consensus);
    }

    #[test]
    fn scope_is_global() {
        assert!(matches!(SkipRequestGossip::SCOPE, TopicScope::Global));
    }
}
