//! Snap-sync beacon-witness history response.

use hyperscale_hbor::{Capped, Hbor};

use crate::{
    BlockHeader, MAX_WITNESSES_PER_FETCH, MessageClass, NetworkMessage, QuorumCertificate,
    ShardWitnessPayload,
};

/// One page of a shard's beacon-witness history at a boundary anchor.
///
/// Ships the leaf *payloads*: the joiner derives each leaf hash for the
/// commitment check and imports the payloads into its own store, so a
/// snap-synced member rebuilds its accumulator across a restart and
/// answers the beacon fold's witness fetches for the window it seeded —
/// an all-cold recovery committee would otherwise hold no payloads below
/// its anchor and starve both. Pages are capped by the payload-sized
/// [`MAX_WITNESSES_PER_FETCH`]; the beacon's own witness fetch pages under
/// no such bound, since a range proof only verifies for the whole run it
/// covers — that path decodes under `MAX_WITNESSES_PER_SHARD` instead.
///
/// The verifier trusts none of it bare: `header` must hash to the
/// beacon-attested anchor `block_hash`, and the hashes of the fully
/// assembled payload vector must merkle to
/// `header.beacon_witness_root()` with exactly
/// `header.beacon_witness_leaf_count()` entries. Individual pages
/// carry no proof — a mismatch at final assembly restarts the fetch.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct WitnessHistoryChunk {
    /// The boundary block's header. Hash-bound to the anchor; its
    /// `beacon_witness_root` / `beacon_witness_leaf_count` are the
    /// commitment the assembled history verifies against, and its
    /// `parent_qc` carries the committee-anchor weighted timestamp the
    /// joiner seeds its recovered state with.
    pub header: BlockHeader,
    /// The QC certifying the boundary block — the parent QC the joiner's
    /// first block past the anchor extends. The joiner binds it
    /// structurally (it must certify the anchor `block_hash`, which pins
    /// every certified field through the vote message) but cannot check
    /// the aggregate signature here; the shard coordinator verifies it
    /// against its resolved committee before adopting it as `latest_qc`.
    pub qc: QuorumCertificate,
    /// Leaf payloads from the requested `start_index`, in leaf-index
    /// order.
    pub payloads: Capped<Vec<ShardWitnessPayload>, MAX_WITNESSES_PER_FETCH>,
    /// Whether leaves beyond the last returned remain below the
    /// header's leaf count — the joiner resumes at the next index.
    pub more: bool,
}

/// Response to a
/// [`GetWitnessHistoryRequest`](crate::network::request::GetWitnessHistoryRequest).
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetWitnessHistoryResponse {
    /// The served page, or `None` when this peer cannot serve the
    /// requested anchor (unknown height, fork-divergent hash, or
    /// retention-pruned leaves) — the requester should try a different
    /// peer.
    pub history: Option<WitnessHistoryChunk>,
}

impl NetworkMessage for GetWitnessHistoryResponse {
    fn message_type_id() -> &'static str {
        "witness_history.response"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{
        AggregateSignature, BeaconWitnessLeafCount, BlockHash, BlockHeaderParts, BlockHeight,
        ChainOrigin, Hash, ProposerTimestamp, QuorumCertificate, Round, ShardId, SignerBitfield,
        Stake, StakePoolId, WeightedTimestamp,
    };

    fn make_header() -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(7),
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(1_234_567_890),
            beacon_witness_leaf_count: BeaconWitnessLeafCount::new(2),
            ..Default::default()
        })
    }

    #[test]
    fn test_hbor_roundtrip_unavailable() {
        let response = GetWitnessHistoryResponse { history: None };

        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetWitnessHistoryResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_hbor_roundtrip_chunk() {
        let header = make_header();
        let qc = QuorumCertificate::new(
            header.hash(),
            ShardId::ROOT,
            header.height(),
            header.parent_block_hash(),
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        let response = GetWitnessHistoryResponse {
            history: Some(WitnessHistoryChunk {
                header,
                qc,
                payloads: Capped::from_array([
                    ShardWitnessPayload::StakeDeposit {
                        pool_id: StakePoolId::new(1),
                        amount: Stake::from_whole_tokens(5),
                    },
                    ShardWitnessPayload::StakeDeposit {
                        pool_id: StakePoolId::new(2),
                        amount: Stake::from_whole_tokens(7),
                    },
                ]),
                more: true,
            }),
        };

        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetWitnessHistoryResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
