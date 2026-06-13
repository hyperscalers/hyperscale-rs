//! Settled-wave reveal response for the split-boundary fence.

use sbor::prelude::BasicSbor;

use crate::{
    BoundedVec, CertifiedBlockHeader, MAX_EXECUTION_CERTIFICATES_PER_WAVE,
    MAX_FINALIZED_TX_PER_BLOCK, MessageClass, NetworkMessage, WaveId,
};

/// One committed block's settled-wave reveal.
///
/// Verified, not trusted bare: the requester checks `certified_header`
/// hashes to the expected block hash (chaining back from the
/// beacon-attested terminal), recomputes the header's `certificate_root`
/// from `certs`, and only then reads each certificate's settled wave-id
/// off the verified pairs. The QC inside the header is the requester's
/// (driver's) to verify against P's committee — completeness against the
/// root is what this reveal proves.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SettledWavesReveal {
    /// The block's header paired with its committing QC.
    pub certified_header: CertifiedBlockHeader,
    /// The execution-certificate wave-ids of every wave certificate the
    /// block committed, in block order; the inner list is one
    /// certificate's EC wave-ids in `receipt_hash` order. Reproduces the
    /// header's `certificate_root` and yields each certificate's own
    /// settled wave (the entry whose shard is the serving shard).
    pub certs: BoundedVec<
        BoundedVec<WaveId, MAX_EXECUTION_CERTIFICATES_PER_WAVE>,
        MAX_FINALIZED_TX_PER_BLOCK,
    >,
}

/// Response to a
/// [`GetSettledWavesRequest`](crate::network::request::GetSettledWavesRequest).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetSettledWavesResponse {
    /// The block's reveal, or `None` when this peer doesn't hold the
    /// requested height — the requester rotates to another peer.
    pub reveal: Option<SettledWavesReveal>,
}

impl GetSettledWavesResponse {
    /// A reveal for one committed block.
    #[must_use]
    pub const fn found(reveal: SettledWavesReveal) -> Self {
        Self {
            reveal: Some(reveal),
        }
    }

    /// This peer can't serve the requested height.
    #[must_use]
    pub const fn not_found() -> Self {
        Self { reveal: None }
    }
}

impl NetworkMessage for GetSettledWavesResponse {
    fn message_type_id() -> &'static str {
        "settled_waves.response"
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
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader, BlockHeight,
        CertificateRoot, ChainOrigin, Hash, InFlightCount, LocalReceiptRoot, ProposerTimestamp,
        ProvisionsRoot, QuorumCertificate, Round, ShardId, StateRoot, TransactionRoot, ValidatorId,
        Verifiable,
    };

    fn header() -> BlockHeader {
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
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
        )
    }

    #[test]
    fn test_sbor_roundtrip_not_found() {
        let response = GetSettledWavesResponse::not_found();
        let encoded = basic_encode(&response).unwrap();
        let decoded: GetSettledWavesResponse = basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_sbor_roundtrip_reveal() {
        let wave = WaveId::new(
            ShardId::ROOT,
            BlockHeight::new(7),
            std::iter::empty().collect(),
        );
        let h = header();
        let qc = QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT);
        let response = GetSettledWavesResponse::found(SettledWavesReveal {
            certified_header: CertifiedBlockHeader::new(h, Verifiable::from(qc)),
            certs: vec![vec![wave].into()].into(),
        });
        let encoded = basic_encode(&response).unwrap();
        let decoded: GetSettledWavesResponse = basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
