//! Local provisions fetch response (intra-shard DA).

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{
    BoundedVec, CertifiedBlockHeader, MAX_PROVISIONS_PER_BLOCK, MessageClass, NetworkMessage,
    Provisions,
};

/// One returned batch plus the source-shard header that proved its
/// provisions root.
///
/// The follower fetching a local provision is reacting to the block
/// proposer's manifest — they don't necessarily have the matching source
/// remote header yet (gossip races mean it can arrive after the proposal).
/// The responder, by construction, *does* have it: a provision sits in
/// `provision_store` only because admission succeeded, and admission
/// gates on the verified source header. Carrying the header inline lets
/// the receiver verify and admit in one shot, skipping the pipeline
/// buffer entirely.
///
/// `source_header` is `Option` so a responder that has GC'd the header
/// after admitting the batch can still serve the blob — the receiver
/// gracefully falls back to the buffered path (which now correctly
/// fails out on terminal drops).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct LocalProvisionEntry {
    /// The provisions batch.
    pub provisions: Arc<Provisions>,
    /// The source-shard committed header at `provisions.block_height()`,
    /// if the responder still has it.
    pub source_header: Option<Arc<CertifiedBlockHeader>>,
}

/// Response to a local provisions fetch request.
///
/// `entries` holds the batches the responder has plus the matching source
/// header for each. The requester knows the hashes it asked for, so missing
/// hashes are computed client-side as `requested - returned`; the wire
/// format does not duplicate that diff.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetLocalProvisionsResponse {
    /// Provision batches the responder had locally, each paired with the
    /// source-shard header that proved its provisions root (when still
    /// retained).
    ///
    /// Capped at [`MAX_PROVISIONS_PER_BLOCK`] — the natural ceiling since a
    /// single block can't reference more provisions than this, and the fetch
    /// dispatcher chunks at 16 ids per call.
    pub entries: BoundedVec<LocalProvisionEntry, MAX_PROVISIONS_PER_BLOCK>,
}

impl GetLocalProvisionsResponse {
    /// Build a response carrying `entries`.
    ///
    /// # Panics
    ///
    /// Panics if `entries.len() > MAX_PROVISIONS_PER_BLOCK`. The fetch
    /// dispatcher chunks at 16 ids per call, so well-behaved callers sit
    /// far below the cap.
    #[must_use]
    pub fn new(entries: Vec<LocalProvisionEntry>) -> Self {
        Self {
            entries: entries.into(),
        }
    }

    /// Build an empty response (responder had none of the requested batches).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: BoundedVec::new(),
        }
    }
}

impl NetworkMessage for GetLocalProvisionsResponse {
    fn message_type_id() -> &'static str {
        "local_provision.response"
    }

    fn class() -> MessageClass {
        MessageClass::BlockCompletion
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder as _,
        NoCustomValueKind, ValueKind, VecEncoder, basic_decode, basic_encode,
    };

    use super::*;

    #[test]
    fn test_empty_response() {
        let resp = GetLocalProvisionsResponse::empty();
        assert!(resp.entries.is_empty());
    }

    #[test]
    fn empty_response_roundtrips() {
        let original = GetLocalProvisionsResponse::empty();
        let bytes = basic_encode(&original).unwrap();
        let decoded: GetLocalProvisionsResponse = basic_decode(&bytes).unwrap();
        assert!(decoded.entries.is_empty());
    }

    #[test]
    fn entry_with_bundled_header_roundtrips() {
        use crate::{
            BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader, BlockHeight,
            CertificateRoot, CertifiedBlockHeader, Hash, InFlightCount, LocalReceiptRoot,
            MerkleInclusionProof, ProposerTimestamp, ProvisionEntry, ProvisionsRoot,
            QuorumCertificate, Round, ShardGroupId, SignerBitfield, StateRoot, TransactionRoot,
            TxHash, ValidatorId, WeightedTimestamp, zero_bls_signature,
        };

        let source_shard = ShardGroupId::new(1);
        let target_shard = ShardGroupId::new(0);
        let source_height = BlockHeight::new(7);
        let provisions = Arc::new(Provisions::new(
            source_shard,
            target_shard,
            source_height,
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from_raw(Hash::from_bytes(b"tx")),
                vec![],
                vec![],
                vec![],
            )],
        ));
        let header = BlockHeader::new(
            source_shard,
            source_height,
            BlockHash::ZERO,
            QuorumCertificate::genesis(source_shard),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(0),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
        );
        let header_hash = header.hash();
        let qc = QuorumCertificate::new(
            header_hash,
            source_shard,
            source_height,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );
        let source_header = Arc::new(CertifiedBlockHeader::new(header, qc));

        let original = GetLocalProvisionsResponse::new(vec![LocalProvisionEntry {
            provisions: Arc::clone(&provisions),
            source_header: Some(Arc::clone(&source_header)),
        }]);
        let bytes = basic_encode(&original).unwrap();
        let decoded: GetLocalProvisionsResponse = basic_decode(&bytes).unwrap();
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].provisions.hash(), provisions.hash());
        let decoded_header = decoded.entries[0]
            .source_header
            .as_ref()
            .expect("header bundled");
        assert_eq!(
            decoded_header.header().hash(),
            source_header.header().hash()
        );

        // Same shape with `None` header — the responder GC'd it after admit.
        let stripped = GetLocalProvisionsResponse::new(vec![LocalProvisionEntry {
            provisions: Arc::clone(&provisions),
            source_header: None,
        }]);
        let bytes = basic_encode(&stripped).unwrap();
        let decoded: GetLocalProvisionsResponse = basic_decode(&bytes).unwrap();
        assert!(decoded.entries[0].source_header.is_none());
    }

    /// Hand-roll a response whose `entries` length exceeds the cap. The
    /// `BoundedVec` decoder fires before any per-entry decode work happens.
    #[test]
    fn decode_rejects_oversized_entry_count() {
        let mut buf = Vec::with_capacity(32);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(1).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(MAX_PROVISIONS_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<GetLocalProvisionsResponse>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_PROVISIONS_PER_BLOCK
                    && actual == MAX_PROVISIONS_PER_BLOCK + 1
        ));
    }
}
