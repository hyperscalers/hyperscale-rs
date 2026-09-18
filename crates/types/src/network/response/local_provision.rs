//! Local provisions fetch response (intra-shard DA).

use std::sync::Arc;

use hyperscale_hbor::{Capped, Hbor};

use crate::{
    CertifiedBlockHeader, MAX_PROVISIONS_PER_BLOCK, MessageClass, NetworkMessage, Provisions,
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
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct LocalProvisionEntry {
    /// The provisions batch.
    pub provisions: Arc<Provisions>,
    /// The source-shard certified header at `provisions.block_height()`,
    /// if the responder still has it.
    pub source_header: Option<Arc<CertifiedBlockHeader>>,
}

/// Response to a local provisions fetch request.
///
/// `entries` holds the batches the responder has plus the matching source
/// header for each. The requester knows the hashes it asked for, so missing
/// hashes are computed client-side as `requested - returned`; the wire
/// format does not duplicate that diff.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetLocalProvisionsResponse {
    /// Provision batches the responder had locally, each paired with the
    /// source-shard header that proved its provisions root (when still
    /// retained).
    ///
    /// Capped at [`MAX_PROVISIONS_PER_BLOCK`] — the natural ceiling since a
    /// single block can't reference more provisions than this, and the fetch
    /// dispatcher chunks at 16 ids per call.
    pub entries: Capped<Vec<LocalProvisionEntry>, MAX_PROVISIONS_PER_BLOCK>,
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
    pub const fn new(entries: Capped<Vec<LocalProvisionEntry>, MAX_PROVISIONS_PER_BLOCK>) -> Self {
        Self { entries }
    }

    /// Build an empty response (responder had none of the requested batches).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: Capped::empty(),
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
    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use super::*;
    use crate::AggregateSignature;

    #[test]
    fn test_empty_response() {
        let resp = GetLocalProvisionsResponse::empty();
        assert!(resp.entries.is_empty());
    }

    #[test]
    fn empty_response_roundtrips() {
        let original = GetLocalProvisionsResponse::empty();
        let bytes = hbor_to_vec(&original).unwrap();
        let decoded: GetLocalProvisionsResponse = hbor_from_slice(&bytes).unwrap();
        assert!(decoded.entries.is_empty());
    }

    #[test]
    fn entry_with_bundled_header_roundtrips() {
        use crate::{
            BlockHash, BlockHeader, BlockHeaderParts, BlockHeight, CertifiedBlockHeader,
            ChainOrigin, Hash, MerkleInclusionProof, ProposerTimestamp, ProvisionEntry,
            QuorumCertificate, Round, ShardId, SignerBitfield, TxHash, WeightedTimestamp,
        };

        let source_shard = ShardId::leaf(1, 1);
        let target_shard = ShardId::leaf(1, 0);
        let source_height = BlockHeight::new(7);
        let provisions = Arc::new(Provisions::new(
            source_shard,
            target_shard,
            source_height,
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from(Hash::from_bytes(b"tx")),
                vec![],
            )],
        ));
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: source_shard,
            height: source_height,
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(source_shard, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(0),
            provision_tx_roots: Capped::default(),
            ..Default::default()
        });
        let header_hash = header.hash();
        let qc = QuorumCertificate::new(
            header_hash,
            source_shard,
            source_height,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        let source_header = Arc::new(CertifiedBlockHeader::new(header, qc));

        let original = GetLocalProvisionsResponse::new(Capped::from_array([LocalProvisionEntry {
            provisions: Arc::clone(&provisions),
            source_header: Some(Arc::clone(&source_header)),
        }]));
        let bytes = hbor_to_vec(&original).unwrap();
        let decoded: GetLocalProvisionsResponse = hbor_from_slice(&bytes).unwrap();
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
        let stripped = GetLocalProvisionsResponse::new(Capped::from_array([LocalProvisionEntry {
            provisions: Arc::clone(&provisions),
            source_header: None,
        }]));
        let bytes = hbor_to_vec(&stripped).unwrap();
        let decoded: GetLocalProvisionsResponse = hbor_from_slice(&bytes).unwrap();
        assert!(decoded.entries[0].source_header.is_none());
    }

    /// Hand-roll a response whose `entries` length exceeds the cap. The
    /// bound check fires before any per-entry decode work happens.
    #[test]
    fn decode_rejects_oversized_entry_count() {
        let mut buf = Vec::new();
        varint::write(&mut buf, MAX_PROVISIONS_PER_BLOCK + 1).unwrap();
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_PROVISIONS_PER_BLOCK + 1) * 256,
        ));
        let err = hbor_from_slice::<GetLocalProvisionsResponse>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_PROVISIONS_PER_BLOCK
                    && actual == MAX_PROVISIONS_PER_BLOCK + 1
        ));
    }
}
