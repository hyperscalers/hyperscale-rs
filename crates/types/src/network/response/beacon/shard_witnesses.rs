//! Shard-witness fetch response.

use hyperscale_hbor::{Capped, Hbor};

use crate::{
    Hash, MAX_RANGE_PROOF_NODES, MAX_WITNESSES_PER_SHARD, MessageClass, NetworkMessage,
    ShardWitnessPayload,
};

/// Response to a
/// [`GetShardWitnessesRequest`](crate::network::request::beacon::GetShardWitnessesRequest).
///
/// Carries a contiguous run of witness payloads starting at the request's
/// `lo`, with one range proof lifting them to the requested block's
/// [`BeaconWitnessRoot`](crate::BeaconWitnessRoot). Leaf positions are
/// implied by `lo` and the payload order, so the requester verifies
/// against the window it already resolved from the anchor header.
///
/// The run is served whole: the requester admits a chunk only when it
/// covers exactly the range the fold will apply, so a prefix would be
/// dropped on arrival. A responder that can't cover the request clamps to
/// what its window holds, and the requester re-requests against a later
/// anchor. Empty when the responder can serve nothing at the named
/// committed block, in which case the requester falls through to another
/// peer in the shard's committee.
///
/// The run's width is bounded by the fold's per-epoch budget
/// ([`MAX_WITNESSES_PER_SHARD`]) — the same bound the beacon block itself
/// carries, so a servable chunk always fits in the block that commits it.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetShardWitnessesResponse {
    /// Witness payloads in leaf-index order, starting at the request's
    /// `lo`.
    pub payloads: Capped<Vec<ShardWitnessPayload>, MAX_WITNESSES_PER_SHARD>,
    /// Flanking merkle nodes lifting `payloads` to the anchor block's
    /// beacon-witness root.
    pub range_proof: Capped<Vec<Hash>, MAX_RANGE_PROOF_NODES>,
}

impl GetShardWitnessesResponse {
    /// Build a response from a payload run and its range proof.
    ///
    /// # Panics
    ///
    /// Panics if `payloads.len() > MAX_WITNESSES_PER_SHARD` or
    /// `range_proof.len() > MAX_RANGE_PROOF_NODES`.
    #[must_use]
    pub const fn new(
        payloads: Capped<Vec<ShardWitnessPayload>, MAX_WITNESSES_PER_SHARD>,
        range_proof: Capped<Vec<Hash>, MAX_RANGE_PROOF_NODES>,
    ) -> Self {
        Self {
            payloads,
            range_proof,
        }
    }

    /// Empty response — responder can serve nothing at the named block.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            payloads: Capped::empty(),
            range_proof: Capped::empty(),
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
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{Stake, StakePoolId};

    fn sample_payload(pool: u32) -> ShardWitnessPayload {
        ShardWitnessPayload::StakeDeposit {
            pool_id: StakePoolId::new(pool),
            amount: Stake::from_whole_tokens(1_000),
        }
    }

    #[test]
    fn hbor_round_trip_populated() {
        let resp = GetShardWitnessesResponse::new(
            Capped::from_array([sample_payload(1), sample_payload(2), sample_payload(42)]),
            Capped::from_array([Hash::from_bytes(b"flank0"), Hash::from_bytes(b"flank1")]),
        );
        let bytes = hbor_to_vec(&resp).unwrap();
        let decoded: GetShardWitnessesResponse = hbor_from_slice(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn hbor_round_trip_empty() {
        let resp = GetShardWitnessesResponse::empty();
        let bytes = hbor_to_vec(&resp).unwrap();
        let decoded: GetShardWitnessesResponse = hbor_from_slice(&bytes).unwrap();
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
