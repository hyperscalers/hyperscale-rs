//! Hash-level block contents (`BlockManifest`) and denormalized storage form
//! (`BlockMetadata`).

use crate::{
    Block, BlockHash, BlockHeader, BlockHeight, ProvisionHash, QuorumCertificate, TxHash,
    WaveIdHash,
};
use sbor::prelude::*;

/// Hash-level description of a block's contents (transactions and certificates).
///
/// This is the common denominator shared by `BlockHeaderNotification`, `BlockMetadata`,
/// and `ProtocolEvent::BlockHeaderReceived`. Extracting it into a standalone type
/// eliminates copy-paste across those sites.
#[derive(Debug, Clone, Default, PartialEq, Eq, BasicSbor)]
pub struct BlockManifest {
    /// Transaction hashes in block order.
    pub tx_hashes: Vec<TxHash>,

    /// Certificate hashes (`wave_id` hashes) in block order.
    /// Validators use these to match against their locally finalized waves.
    pub cert_hashes: Vec<WaveIdHash>,

    /// Hashes of provisions included in this block.
    /// Used for provision data availability — validators fetch missing batches by hash.
    pub provision_hashes: Vec<ProvisionHash>,
}

impl BlockManifest {
    /// Get total transaction count.
    #[must_use]
    pub const fn transaction_count(&self) -> usize {
        self.tx_hashes.len()
    }

    /// Build a manifest from a full block (extracting hashes).
    ///
    /// `cert_hashes` uses `wave_id` identity hashes (computable without EC knowledge).
    #[must_use]
    pub fn from_block(block: &Block) -> Self {
        Self {
            tx_hashes: block.transactions().iter().map(|tx| tx.hash()).collect(),
            cert_hashes: block
                .certificates()
                .iter()
                .map(|c| c.wave_id().hash())
                .collect(),
            provision_hashes: vec![],
        }
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
    /// Block header (contains height, parent hash, proposer, etc.)
    pub header: BlockHeader,

    /// Block contents (transaction hashes, certificates, deferrals, etc.)
    pub manifest: BlockManifest,

    /// Quorum certificate that commits this block.
    pub qc: QuorumCertificate,
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
