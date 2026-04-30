//! A block paired with the quorum certificate that certifies it.
//!
//! Every committed block has exactly one QC where `qc.block_hash == block.hash()`.

use crate::{Block, BlockHash, BlockHeight, QuorumCertificate};
use sbor::prelude::*;

/// A block alongside the QC that certifies it.
///
/// Invariant: `qc.block_hash == block.hash()`. The invariant is checked by
/// `new_checked`; fields are `pub` so wire deserialization and other paths
/// that rely on separate structural/cryptographic verification can still
/// construct the type directly.
///
/// Note this is *not* the same as the `parent_qc` stored inside a block's
/// header — that QC certifies the *parent* block. The QC on a `CertifiedBlock`
/// certifies the block it's paired with.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct CertifiedBlock {
    /// The certified block.
    pub block: Block,
    /// QC certifying [`Self::block`]. Invariant: `qc.block_hash == block.hash()`.
    pub qc: QuorumCertificate,
}

/// Error returned when the block hash doesn't match the QC's `block_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertifiedBlockHashMismatch {
    /// Hash computed from the block's content.
    pub block_hash: BlockHash,
    /// Hash carried by the QC.
    pub qc_block_hash: BlockHash,
}

impl CertifiedBlock {
    /// Construct after verifying the structural pairing invariant.
    ///
    /// Does not verify the QC's cryptographic signature — that's the
    /// responsibility of the sync / BFT verification pipelines.
    ///
    /// # Errors
    ///
    /// Returns [`CertifiedBlockHashMismatch`] if `qc.block_hash` does
    /// not match `block.hash()`.
    pub fn new_checked(
        block: Block,
        qc: QuorumCertificate,
    ) -> Result<Self, CertifiedBlockHashMismatch> {
        let block_hash = block.hash();
        if qc.block_hash != block_hash {
            return Err(CertifiedBlockHashMismatch {
                block_hash,
                qc_block_hash: qc.block_hash,
            });
        }
        Ok(Self { block, qc })
    }

    /// Pair a block with its QC, panicking if `qc.block_hash` doesn't
    /// match `block.hash()`. For call sites where the pair is built
    /// together (genesis, freshly produced blocks, test fixtures) and
    /// a mismatch indicates a programming error. Use [`new_checked`]
    /// for any path that consumes externally-sourced QC/block pairs
    /// (wire decode, storage load).
    ///
    /// [`new_checked`]: Self::new_checked
    ///
    /// # Panics
    ///
    /// Panics if `qc.block_hash != block.hash()`.
    #[must_use]
    pub fn new_unchecked(block: Block, qc: QuorumCertificate) -> Self {
        assert_eq!(
            qc.block_hash,
            block.hash(),
            "CertifiedBlock pairing invariant"
        );
        Self { block, qc }
    }

    /// The block's height.
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.block.height()
    }

    /// The block's hash.
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        self.block.hash()
    }
}
