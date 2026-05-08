//! Hash-level block contents (`BlockManifest`) and denormalized storage form
//! (`BlockMetadata`).

use sbor::prelude::*;

use crate::{
    Block, BlockHash, BlockHeader, BlockHeight, BoundedVec, MAX_FINALIZED_TX_PER_BLOCK,
    MAX_PROVISIONS_PER_BLOCK, MAX_TXS_PER_BLOCK, ProvisionHash, QuorumCertificate, TxHash, WaveId,
};

/// Hash-level description of a block's contents (transactions and certificates).
///
/// This is the common denominator shared by `BlockHeaderNotification`, `BlockMetadata`,
/// and `ProtocolEvent::BlockHeaderReceived`. Extracting it into a standalone type
/// eliminates copy-paste across those sites.
///
/// Per-collection caps mirror [`Block`]'s caps one-to-one — a manifest is a
/// hash-only projection of a `Block` and inherits its natural ceilings.
#[derive(Debug, Clone, Default, PartialEq, Eq, BasicSbor)]
pub struct BlockManifest {
    tx_hashes: BoundedVec<TxHash, MAX_TXS_PER_BLOCK>,
    cert_ids: BoundedVec<WaveId, MAX_FINALIZED_TX_PER_BLOCK>,
    provision_hashes: BoundedVec<ProvisionHash, MAX_PROVISIONS_PER_BLOCK>,
}

impl BlockManifest {
    /// Build a manifest from its parts.
    ///
    /// # Panics
    ///
    /// Panics if any input vec exceeds its bounded cap.
    #[must_use]
    pub fn new(
        tx_hashes: Vec<TxHash>,
        cert_ids: Vec<WaveId>,
        provision_hashes: Vec<ProvisionHash>,
    ) -> Self {
        Self {
            tx_hashes: tx_hashes.into(),
            cert_ids: cert_ids.into(),
            provision_hashes: provision_hashes.into(),
        }
    }

    /// Transaction hashes in block order.
    #[must_use]
    pub const fn tx_hashes(&self) -> &BoundedVec<TxHash, MAX_TXS_PER_BLOCK> {
        &self.tx_hashes
    }

    /// Wave identifiers in block order.
    /// Validators use these to match against their locally finalized waves.
    #[must_use]
    pub const fn cert_ids(&self) -> &BoundedVec<WaveId, MAX_FINALIZED_TX_PER_BLOCK> {
        &self.cert_ids
    }

    /// Hashes of provisions included in this block.
    /// Used for provision data availability — validators fetch missing batches by hash.
    #[must_use]
    pub const fn provision_hashes(&self) -> &BoundedVec<ProvisionHash, MAX_PROVISIONS_PER_BLOCK> {
        &self.provision_hashes
    }

    /// Get total transaction count.
    #[must_use]
    pub const fn transaction_count(&self) -> usize {
        self.tx_hashes.len()
    }

    /// Build a manifest from a full block (extracting hashes).
    #[must_use]
    pub fn from_block(block: &Block) -> Self {
        // The source `Block` collections are themselves `BoundedVec`s capped
        // at the same limits, so `.into()` cannot panic — the iterator
        // can't outproduce its source.
        let tx_hashes: Vec<_> = block.transactions().iter().map(|tx| tx.hash()).collect();
        let cert_ids: Vec<_> = block
            .certificates()
            .iter()
            .map(|c| c.wave_id().clone())
            .collect();
        Self::new(tx_hashes, cert_ids, vec![])
    }
}

/// Denormalized block metadata for efficient storage.
///
/// Unlike `Block`, this stores only hashes for transactions and certificates,
/// which are stored separately in their own column families. This eliminates
/// duplication and enables direct lookups.
///
/// # Storage Layout
///
/// - `"blocks"` CF: `BlockMetadata` (this struct) keyed by height
/// - `"transactions"` CF: `RoutableTransaction` keyed by `tx_hash`
/// - `"wave_certificates"` CF: `WaveCertificate` keyed by `wave_id` hash
///
/// To reconstruct a full `Block`, fetch the metadata, then batch-fetch
/// transactions and certificates using the stored hashes.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockMetadata {
    header: BlockHeader,
    manifest: BlockManifest,
    qc: QuorumCertificate,
}

impl BlockMetadata {
    /// Create metadata from a full block and QC.
    #[must_use]
    pub fn from_block(block: &Block, qc: QuorumCertificate) -> Self {
        Self {
            header: block.header().clone(),
            manifest: BlockManifest::from_block(block),
            qc,
        }
    }

    /// Block header (contains height, parent hash, proposer, etc.)
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Block contents (transaction hashes, certificates, deferrals, etc.)
    #[must_use]
    pub const fn manifest(&self) -> &BlockManifest {
        &self.manifest
    }

    /// Quorum certificate that commits this block.
    #[must_use]
    pub const fn qc(&self) -> &QuorumCertificate {
        &self.qc
    }

    /// Consume the metadata and return its parts.
    #[must_use]
    pub fn into_parts(self) -> (BlockHeader, BlockManifest, QuorumCertificate) {
        (self.header, self.manifest, self.qc)
    }

    /// Get block height.
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Compute hash of this block (hashes the header).
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// Get total transaction count.
    #[must_use]
    pub const fn transaction_count(&self) -> usize {
        self.manifest.transaction_count()
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, Categorize as _, DecodeError,
        Encoder as _, NoCustomValueKind, ValueKind, VecEncoder, basic_decode,
    };

    use super::*;

    /// Hand-roll a `BlockManifest` whose `tx_hashes` length prefix exceeds
    /// the cap. The `BoundedVec` decoder fires before any per-element
    /// allocation.
    #[test]
    fn decode_rejects_oversized_tx_hashes_count() {
        let mut buf = Vec::with_capacity(32);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(3).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(TxHash::value_kind()).unwrap();
            enc.write_size(MAX_TXS_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<BlockManifest>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_TXS_PER_BLOCK && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_cert_ids_count() {
        let mut buf = Vec::with_capacity(32);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(3).unwrap();
            // Empty tx_hashes.
            enc.encode(&Vec::<TxHash>::new()).unwrap();
            // Oversized cert_ids.
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(WaveId::value_kind()).unwrap();
            enc.write_size(MAX_FINALIZED_TX_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<BlockManifest>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_FINALIZED_TX_PER_BLOCK
                    && actual == MAX_FINALIZED_TX_PER_BLOCK + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_provision_hashes_count() {
        let mut buf = Vec::with_capacity(32);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(3).unwrap();
            enc.encode(&Vec::<TxHash>::new()).unwrap();
            enc.encode(&Vec::<WaveId>::new()).unwrap();
            // Oversized provision_hashes.
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ProvisionHash::value_kind()).unwrap();
            enc.write_size(MAX_PROVISIONS_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<BlockManifest>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_PROVISIONS_PER_BLOCK
                    && actual == MAX_PROVISIONS_PER_BLOCK + 1
        ));
    }
}
