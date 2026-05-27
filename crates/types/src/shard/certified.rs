//! A block paired with the quorum certificate that certifies it.
//!
//! Every committed block has exactly one QC where `qc.block_hash == block.hash()`.

use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::{
    Block, BlockHash, BlockHeight, QuorumCertificate, Verifiable, VerifiedQuorumCertificate,
};

/// A block alongside the QC that certifies it.
///
/// Invariant: `qc.block_hash == block.hash()`. Enforced at every entry point —
/// [`Self::new_checked`] for in-process construction and the wire decoder
/// below for peer-supplied bytes. Without the decode-side check a Byzantine
/// peer can ship a synced block paired with a forged "genesis QC"
/// (`qc.block_hash == ZERO`, `qc.height == 0`) for an arbitrary block height,
/// bypassing every gate keyed on `qc.is_genesis()` (e.g. the synced-block
/// quorum-power gate in `shard::coordinator`).
///
/// Note this is *not* the same as the `parent_qc` stored inside a block's
/// header — that QC certifies the *parent* block. The QC on a `CertifiedBlock`
/// certifies the block it's paired with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedBlock {
    block: Block,
    qc: Verifiable<QuorumCertificate, VerifiedQuorumCertificate>,
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
    /// responsibility of the sync / shard consensus verification pipelines.
    ///
    /// # Errors
    ///
    /// Returns [`CertifiedBlockHashMismatch`] if `qc.block_hash` does
    /// not match `block.hash()`.
    pub fn new_checked(
        block: Block,
        qc: impl Into<Verifiable<QuorumCertificate, VerifiedQuorumCertificate>>,
    ) -> Result<Self, CertifiedBlockHashMismatch> {
        let qc = qc.into();
        let block_hash = block.hash();
        let qc_block_hash = qc.as_unverified().block_hash();
        if qc_block_hash != block_hash {
            return Err(CertifiedBlockHashMismatch {
                block_hash,
                qc_block_hash,
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
    pub fn new_unchecked(
        block: Block,
        qc: impl Into<Verifiable<QuorumCertificate, VerifiedQuorumCertificate>>,
    ) -> Self {
        let qc = qc.into();
        assert_eq!(
            qc.as_unverified().block_hash(),
            block.hash(),
            "CertifiedBlock pairing invariant"
        );
        Self { block, qc }
    }

    /// Block whose hash matches `qc.block_hash`.
    #[must_use]
    pub const fn block(&self) -> &Block {
        &self.block
    }

    /// QC certifying [`Self::block`]. Invariant: `qc.block_hash == block.hash()`.
    ///
    /// Returns the raw QC regardless of verification status; verified-aware
    /// callers should use [`Self::qc_verifiable`] or [`Self::verified_qc`].
    #[must_use]
    pub fn qc(&self) -> &QuorumCertificate {
        self.qc.as_unverified()
    }

    /// Verified handle on the QC.
    #[must_use]
    pub const fn verified_qc(&self) -> Option<&VerifiedQuorumCertificate> {
        self.qc.verified()
    }

    /// Borrow the QC together with its verification marker.
    #[must_use]
    pub const fn qc_verifiable(&self) -> &Verifiable<QuorumCertificate, VerifiedQuorumCertificate> {
        &self.qc
    }

    /// Consume the pair and return its parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Block,
        Verifiable<QuorumCertificate, VerifiedQuorumCertificate>,
    ) {
        (self.block, self.qc)
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

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for CertifiedBlock {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(&self.block)?;
        encoder.encode(&self.qc)?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for CertifiedBlock {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }
        let block: Block = decoder.decode()?;
        let qc: QuorumCertificate = decoder.decode()?;
        // Wire decode always produces an unverified QC; verification
        // happens at the admission layer.
        Self::new_checked(block, qc).map_err(|_| DecodeError::InvalidCustomValue)
    }
}

impl Categorize<NoCustomValueKind> for CertifiedBlock {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for CertifiedBlock {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("CertifiedBlock", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}
