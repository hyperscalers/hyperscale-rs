//! Shard-witness fetch request — beacon validator pulls witnesses
//! lifted by a shard whose committee they're not a member of.

use sbor::prelude::BasicSbor;

use crate::network::response::beacon::GetShardWitnessesResponse;
use crate::{
    BlockHash, BoundedVec, LeafIndex, MAX_WITNESSES_PER_FETCH, MessageClass, NetworkMessage,
    Request, ShardGroupId,
};

/// Fetch a batch of shard witnesses by leaf index against a specific
/// committed block's accumulator root.
///
/// Served by any validator in `shard_id`'s committee at
/// `committed_block_hash` (the shard's `CommittedBlockHeader` carries
/// the [`BeaconWitnessRoot`](crate::BeaconWitnessRoot) the responder's
/// proofs verify against). Receivers verify each returned witness's
/// inclusion proof against the root in the same committed block they
/// requested.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetShardWitnessesRequest {
    /// Shard whose witnesses are being fetched.
    pub shard_id: ShardGroupId,
    /// Committed block whose accumulator root anchors the requested
    /// proofs. The responder's returned witnesses are proofs against
    /// this block's root, not the responder's current tip.
    pub committed_block_hash: BlockHash,
    /// Positions in `shard_id`'s monotonic beacon-witness accumulator
    /// to fetch. Sorted distinct ascending is conventional but not
    /// required.
    pub leaf_indices: BoundedVec<LeafIndex, MAX_WITNESSES_PER_FETCH>,
}

impl GetShardWitnessesRequest {
    /// Build a request from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `leaf_indices.len() > MAX_WITNESSES_PER_FETCH`.
    #[must_use]
    pub fn new(
        shard_id: ShardGroupId,
        committed_block_hash: BlockHash,
        leaf_indices: Vec<LeafIndex>,
    ) -> Self {
        Self {
            shard_id,
            committed_block_hash,
            leaf_indices: leaf_indices.into(),
        }
    }
}

impl NetworkMessage for GetShardWitnessesRequest {
    fn message_type_id() -> &'static str {
        "beacon.shard_witnesses.request"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl Request for GetShardWitnessesRequest {
    type Response = GetShardWitnessesResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.witnesses.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;

    #[test]
    fn sbor_round_trip() {
        let req = GetShardWitnessesRequest::new(
            ShardGroupId::new(2),
            BlockHash::ZERO,
            vec![LeafIndex::new(1), LeafIndex::new(7), LeafIndex::new(42)],
        );
        let bytes = basic_encode(&req).unwrap();
        let decoded: GetShardWitnessesRequest = basic_decode(&bytes).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn class_is_cross_shard_progress() {
        assert_eq!(
            GetShardWitnessesRequest::class(),
            MessageClass::CrossShardProgress
        );
    }
}
