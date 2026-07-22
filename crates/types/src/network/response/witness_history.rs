//! Snap-sync beacon-witness history response.

use sbor::prelude::BasicSbor;

use crate::{
    BlockHeader, BoundedVec, MAX_WITNESSES_PER_FETCH, MessageClass, NetworkMessage,
    QuorumCertificate, ShardWitnessPayload,
};

/// One page of a shard's beacon-witness history at a boundary anchor.
///
/// Ships the leaf *payloads*: the joiner derives each leaf hash for the
/// commitment check and imports the payloads into its own store, so a
/// snap-synced member rebuilds its accumulator across a restart and
/// answers the beacon fold's witness fetches for the window it seeded —
/// an all-cold recovery committee would otherwise hold no payloads below
/// its anchor and starve both. Pages are capped by the payload-sized
/// [`MAX_WITNESSES_PER_FETCH`], the bound the beacon's own witness fetch
/// decodes under.
///
/// The verifier trusts none of it bare: `header` must hash to the
/// beacon-attested anchor `block_hash`, and the hashes of the fully
/// assembled payload vector must merkle to
/// `header.beacon_witness_root()` with exactly
/// `header.beacon_witness_leaf_count()` entries. Individual pages
/// carry no proof — a mismatch at final assembly restarts the fetch.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
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
    pub payloads: BoundedVec<ShardWitnessPayload, MAX_WITNESSES_PER_FETCH>,
    /// Whether leaves beyond the last returned remain below the
    /// header's leaf count — the joiner resumes at the next index.
    pub more: bool,
}

/// Response to a
/// [`GetWitnessHistoryRequest`](crate::network::request::GetWitnessHistoryRequest).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
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
    use std::collections::BTreeMap;

    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeight, CertificateRoot,
        ChainOrigin, Hash, InFlightCount, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot,
        QuorumCertificate, Round, ShardId, SignerBitfield, Stake, StakePoolId, StateRoot,
        TransactionRoot, ValidatorId, WeightedTimestamp, zero_bls_signature,
    };

    fn make_header() -> BlockHeader {
        BlockHeader::new(
            ShardId::ROOT,
            BlockHeight::new(7),
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_234_567_890),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::new(2),
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        )
    }

    #[test]
    fn test_sbor_roundtrip_unavailable() {
        let response = GetWitnessHistoryResponse { history: None };

        let encoded = basic_encode(&response).unwrap();
        let decoded: GetWitnessHistoryResponse = basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_sbor_roundtrip_chunk() {
        let header = make_header();
        let qc = QuorumCertificate::new(
            header.hash(),
            ShardId::ROOT,
            header.height(),
            header.parent_block_hash(),
            Round::INITIAL,
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );
        let response = GetWitnessHistoryResponse {
            history: Some(WitnessHistoryChunk {
                header,
                qc,
                payloads: vec![
                    ShardWitnessPayload::StakeDeposit {
                        pool_id: StakePoolId::new(1),
                        amount: Stake::from_whole_tokens(5),
                    },
                    ShardWitnessPayload::StakeDeposit {
                        pool_id: StakePoolId::new(2),
                        amount: Stake::from_whole_tokens(7),
                    },
                ]
                .into(),
                more: true,
            }),
        };

        let encoded = basic_encode(&response).unwrap();
        let decoded: GetWitnessHistoryResponse = basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
