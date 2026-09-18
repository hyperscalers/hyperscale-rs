//! Request for a state proof of named keys at a committed height.
//!
//! The requester already holds the commit-proven header for the height
//! and checks the answer against its state root, so the request names
//! nothing but the height and the keys: a peer on another branch at
//! that height serves a proof that fails to reconstruct the root and is
//! rotated off. The answer is a multiproof covering every key asked,
//! inclusion and non-inclusion alike — see
//! [`GetStateProofResponse`](crate::network::response::GetStateProofResponse).

use hyperscale_hbor::{Capped, Hbor};

use crate::network::response::GetStateProofResponse;
use crate::{
    BlockHeight, MAX_PROOFS_PER_QUERY, MessageClass, NetworkMessage, Request, ShardId, SubstateKey,
};

/// The keys to prove and the committed height to prove them at.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetStateProofRequest {
    /// The committed height whose state root the proof reconstructs.
    pub height: BlockHeight,
    /// The keys to prove, present or absent.
    pub keys: Capped<Vec<SubstateKey>, MAX_PROOFS_PER_QUERY>,
}

impl GetStateProofRequest {
    /// A request for `keys` at `height`.
    #[must_use]
    pub const fn new(
        height: BlockHeight,
        keys: Capped<Vec<SubstateKey>, MAX_PROOFS_PER_QUERY>,
    ) -> Self {
        Self { height, keys }
    }
}

impl NetworkMessage for GetStateProofRequest {
    fn message_type_id() -> &'static str {
        "state_proof.request"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl Request for GetStateProofRequest {
    type Response = GetStateProofResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.proof.is_none()
    }
}

/// The keys to prove, the shard whose state holds them, and the
/// committed height to prove them at — asked of this shard's own
/// committee rather than of that shard.
///
/// A block states what a counterpart's committed state said, and a voter
/// holds the statement to a proof it walked itself. Ordinarily that
/// proof comes from the counterpart, but a validator that cannot reach
/// it would have nothing to vote on, so a peer that already fetched one
/// relays its copy. Naming the shard is what separates this from
/// [`GetStateProofRequest`]: the answer is not about the responder's own
/// tree, and the responder can only pass on what it holds.
///
/// Nothing is trusted in the passing. The requester checks the proof
/// against the state root of the header it commit-proved for the height,
/// exactly as it would a proof from the shard itself.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetRelayedStateProofRequest {
    /// The shard whose committed state the proof is about.
    pub shard: ShardId,
    /// The committed height whose state root the proof reconstructs.
    pub height: BlockHeight,
    /// The keys to prove, present or absent.
    pub keys: Capped<Vec<SubstateKey>, MAX_PROOFS_PER_QUERY>,
}

impl GetRelayedStateProofRequest {
    /// A request for `keys` at `shard`'s `height`.
    #[must_use]
    pub const fn new(
        shard: ShardId,
        height: BlockHeight,
        keys: Capped<Vec<SubstateKey>, MAX_PROOFS_PER_QUERY>,
    ) -> Self {
        Self {
            shard,
            height,
            keys,
        }
    }
}

impl NetworkMessage for GetRelayedStateProofRequest {
    fn message_type_id() -> &'static str {
        "relayed_state_proof.request"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl Request for GetRelayedStateProofRequest {
    type Response = GetStateProofResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.proof.is_none()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::test_utils::test_key;

    #[test]
    fn test_hbor_roundtrip() {
        let request =
            GetStateProofRequest::new(BlockHeight::new(42), Capped::from_array([test_key(7)]));
        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetStateProofRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
