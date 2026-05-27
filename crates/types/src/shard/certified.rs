//! A block paired with the quorum certificate that certifies it.
//!
//! Every committed block has exactly one QC where `qc.block_hash == block.hash()`.

use std::ops::Deref;

use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};
use thiserror::Error;

use crate::{
    Block, BlockHash, BlockHeight, QuorumCertificate, Verifiable, VerifiedBlock,
    VerifiedQuorumCertificate,
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
    #[must_use]
    pub fn qc(&self) -> &QuorumCertificate {
        self.qc.as_unverified()
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

/// Why [`VerifiedCertifiedBlock::assemble`] rejected its inputs.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum LinkageError {
    /// `qc.block_hash` does not match the paired block's computed hash.
    #[error("qc.block_hash {qc_block_hash:?} does not match block.hash {block_hash:?}")]
    BlockHashMismatch {
        /// Hash computed from the block's content.
        block_hash: BlockHash,
        /// `block_hash` field from the QC.
        qc_block_hash: BlockHash,
    },
}

/// A `CertifiedBlock` whose block contents and QC have both been verified
/// and whose QC↔block linkage has been checked.
///
/// Construction asserts:
/// 1. The block passes its full [`VerifiedBlock`] predicate (header
///    verified, every applicable per-root verifier succeeded).
/// 2. The QC passes its own verification predicate
///    ([`VerifiedQuorumCertificate`]).
/// 3. `qc.block_hash == block.hash()` (structural pairing).
///
/// State-root verification is tracked separately in the verification
/// pipeline and gates voting/commit via the parallel path, but is not
/// folded into this type's predicate — see the doc on [`VerifiedBlock`].
///
/// Construction goes through one of two gates:
///
/// - [`Self::assemble`] — runs the linkage check on a fresh
///   `(VerifiedBlock, VerifiedQuorumCertificate)` pair.
/// - [`Self::new_unchecked`] — audit point reserved for storage-recovery,
///   genesis, and commit-pipeline call sites where the full predicate
///   was established upstream.
///
/// `#[repr(transparent)]` over `CertifiedBlock`: `Deref<Target =
/// CertifiedBlock>` exposes the existing accessors; no mutable access,
/// no `Encode`/`Decode` (this is a runtime-only typestate marker,
/// in-process events only).
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCertifiedBlock(CertifiedBlock);

impl VerifiedCertifiedBlock {
    /// Pair a [`VerifiedBlock`] with a [`VerifiedQuorumCertificate`],
    /// checking the linkage invariant.
    ///
    /// # Errors
    ///
    /// Returns [`LinkageError::BlockHashMismatch`] when `qc.block_hash`
    /// does not equal `block.hash()`.
    pub fn assemble(
        block: VerifiedBlock,
        qc: VerifiedQuorumCertificate,
    ) -> Result<Self, LinkageError> {
        let block = block.into_inner();
        let block_hash = block.hash();
        let qc_block_hash = qc.block_hash();
        if qc_block_hash != block_hash {
            return Err(LinkageError::BlockHashMismatch {
                block_hash,
                qc_block_hash,
            });
        }
        Ok(Self(CertifiedBlock {
            block,
            qc: Verifiable::Verified(qc),
        }))
    }

    /// Audit-point constructor. Skips the predicate.
    ///
    /// Permitted use sites: storage-recovery (full predicate established
    /// before persistence), genesis (locally constructed with empty
    /// content), and commit-pipeline interceptors that produced the
    /// `CertifiedBlock` from inputs already checked at the coordinator
    /// or vote-path layer. Each call site documents the trust source
    /// with a `// SAFETY:` comment; `grep new_unchecked` produces the
    /// audit list.
    #[must_use]
    pub const fn new_unchecked(inner: CertifiedBlock) -> Self {
        Self(inner)
    }

    /// Borrow the underlying [`CertifiedBlock`].
    #[must_use]
    pub const fn as_certified(&self) -> &CertifiedBlock {
        &self.0
    }

    /// Consume the wrapper and return the raw [`CertifiedBlock`].
    #[must_use]
    pub fn into_inner(self) -> CertifiedBlock {
        self.0
    }
}

impl AsRef<CertifiedBlock> for VerifiedCertifiedBlock {
    fn as_ref(&self) -> &CertifiedBlock {
        &self.0
    }
}

impl Deref for VerifiedCertifiedBlock {
    type Target = CertifiedBlock;
    fn deref(&self) -> &CertifiedBlock {
        &self.0
    }
}

impl From<VerifiedCertifiedBlock> for CertifiedBlock {
    fn from(verified: VerifiedCertifiedBlock) -> Self {
        verified.0
    }
}

#[cfg(test)]
mod tests {
    use sbor::basic_encode;

    use super::*;
    use crate::{
        Round, ShardGroupId, SignerBitfield, StateRoot, ValidatorId, WeightedTimestamp,
        zero_bls_signature,
    };

    /// A [`CertifiedBlock`]'s SBOR encoding does not depend on whether its
    /// QC is wrapped as [`Verifiable::Unverified`] or [`Verifiable::Verified`].
    /// This is the invariant that keeps wire bytes (and every merkle root or
    /// signature computed over them) stable across the field's type change
    /// from raw `QuorumCertificate` to `Verifiable<QC, VerifiedQC>`.
    #[test]
    fn wire_bypass_identical_across_verified_states() {
        let block = Block::genesis(ShardGroupId::new(0), ValidatorId::new(0), StateRoot::ZERO);
        let qc = QuorumCertificate::new(
            block.hash(),
            ShardGroupId::new(0),
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );

        let unverified = CertifiedBlock::new_unchecked(block.clone(), qc.clone());
        let verified =
            CertifiedBlock::new_unchecked(block, VerifiedQuorumCertificate::new_unchecked(qc));

        let bytes_unverified = basic_encode(&unverified).unwrap();
        let bytes_verified = basic_encode(&verified).unwrap();
        assert_eq!(bytes_unverified, bytes_verified);
    }
}
