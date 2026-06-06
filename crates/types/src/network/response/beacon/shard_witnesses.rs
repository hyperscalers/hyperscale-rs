//! Shard-witness fetch response.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{BoundedVec, MAX_WITNESSES_PER_FETCH, MessageClass, NetworkMessage, ShardWitness};

/// Response to a
/// [`GetShardWitnessesRequest`](crate::network::request::beacon::GetShardWitnessesRequest).
///
/// Carries each requested witness paired with its inclusion proof
/// against the requested committed block's
/// [`BeaconWitnessRoot`](crate::BeaconWitnessRoot). Each witness's
/// [`ShardWitnessProof`](crate::ShardWitnessProof) names that same
/// `committed_block_hash` so the requester verifies against the root
/// they already hold.
///
/// Order matches the request's `leaf_indices` for trivial caller-side
/// pairing. Empty when the responder has none of the requested
/// witnesses at the named committed block — the requester falls
/// through to another peer in the shard's committee.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetShardWitnessesResponse {
    /// Witnesses with their inclusion proofs.
    pub witnesses: BoundedVec<Arc<ShardWitness>, MAX_WITNESSES_PER_FETCH>,
}

impl GetShardWitnessesResponse {
    /// Build a response from a vector of witnesses.
    ///
    /// # Panics
    ///
    /// Panics if `witnesses.len() > MAX_WITNESSES_PER_FETCH`.
    #[must_use]
    pub fn new(witnesses: Vec<Arc<ShardWitness>>) -> Self {
        Self {
            witnesses: witnesses.into(),
        }
    }

    /// Empty response — responder has none of the requested witnesses.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            witnesses: Vec::new().into(),
        }
    }
}

impl NetworkMessage for GetShardWitnessesResponse {
    fn message_type_id() -> &'static str {
        "beacon.shard_witnesses.response"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::{
        BlockHash, Hash, LeafIndex, ShardGroupId, ShardWitnessPayload, ShardWitnessProof, Stake,
        StakePoolId,
    };

    fn sample_witness(leaf_index: u64) -> Arc<ShardWitness> {
        Arc::new(ShardWitness {
            payload: ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(1),
                amount: Stake::from_whole_tokens(1_000),
            },
            proof: ShardWitnessProof {
                shard_id: ShardGroupId::ROOT,
                committed_block_hash: BlockHash::from_raw(Hash::from_bytes(b"committed")),
                leaf_index: LeafIndex::new(leaf_index),
                siblings: vec![
                    Hash::from_bytes(b"sib0"),
                    Hash::from_bytes(b"sib1"),
                    Hash::from_bytes(b"sib2"),
                ]
                .into(),
            },
        })
    }

    #[test]
    fn sbor_round_trip_populated() {
        let resp = GetShardWitnessesResponse::new(vec![
            sample_witness(1),
            sample_witness(2),
            sample_witness(42),
        ]);
        let bytes = basic_encode(&resp).unwrap();
        let decoded: GetShardWitnessesResponse = basic_decode(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn sbor_round_trip_empty() {
        let resp = GetShardWitnessesResponse::empty();
        let bytes = basic_encode(&resp).unwrap();
        let decoded: GetShardWitnessesResponse = basic_decode(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn class_is_cross_shard_progress() {
        assert_eq!(
            GetShardWitnessesResponse::class(),
            MessageClass::CrossShardProgress
        );
    }
}
