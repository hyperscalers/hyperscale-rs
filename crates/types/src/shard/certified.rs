//! A block paired with the quorum certificate that certifies it.
//!
//! Every committed block has exactly one QC where `qc.block_hash == block.hash()`.

use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};
use thiserror::Error;

use crate::{
    Block, BlockHash, BlockHeight, CertifiedBlockHeader, ChainOrigin, QuorumCertificate, ShardId,
    StateRoot, ValidatorId, Verifiable, Verified,
};

/// A block alongside the QC that certifies it.
///
/// Invariant: `qc.block_hash == block.hash()`. Enforced at every entry point —
/// [`Self::new_checked`] for in-process construction and the wire decoder
/// below for peer-supplied bytes. Without the decode-side check a Byzantine
/// peer can ship a synced block paired with a forged "genesis QC"
/// (`qc.block_hash == ZERO`, empty signers) for an arbitrary block height,
/// bypassing every gate keyed on `qc.is_genesis()` (e.g. the synced-block
/// quorum-power gate in `shard::coordinator`).
///
/// Note this is *not* the same as the `parent_qc` stored inside a block's
/// header — that QC certifies the *parent* block. The QC on a `CertifiedBlock`
/// certifies the block it's paired with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedBlock {
    block: Block,
    qc: Verifiable<QuorumCertificate>,
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
        qc: impl Into<Verifiable<QuorumCertificate>>,
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
    pub fn new_unchecked(block: Block, qc: impl Into<Verifiable<QuorumCertificate>>) -> Self {
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

    /// Borrow the QC's [`Verifiable`] wrapper, exposing the verification
    /// marker. Used by typestate consumers that branch on whether the
    /// QC has already been verified.
    #[must_use]
    pub const fn qc_verifiable(&self) -> &Verifiable<QuorumCertificate> {
        &self.qc
    }

    /// Consume the pair and return its parts.
    #[must_use]
    pub fn into_parts(self) -> (Block, Verifiable<QuorumCertificate>) {
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

/// Why [`Verified::<CertifiedBlock>::assemble`] rejected its inputs.
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

impl Verified<CertifiedBlock> {
    /// Verified form of the genesis `CertifiedBlock` for
    /// `shard_id`.
    ///
    /// Builds the empty genesis block, pairs it with a genesis-shape
    /// QC (zero signers, zero signature, zero round/height) whose
    /// `block_hash` points at the genesis block so the
    /// [`Verified<CertifiedBlock>`] linkage holds. The canonical
    /// [`QuorumCertificate::genesis`] carries `BlockHash::ZERO` and
    /// therefore does not pair directly with a real genesis block;
    /// this constructor handles the substitution.
    ///
    /// Construction asserts the full [`Verified<CertifiedBlock>`]
    /// predicate by inputs: every commitment root is the empty-input
    /// compute, the embedded `parent_qc` is the canonical genesis
    /// (verified by definition), and the synthetic genesis-shape QC
    /// pairs by construction.
    ///
    /// # Panics
    ///
    /// Panics if the assemble linkage fails — structurally impossible
    /// for genesis pairs.
    #[must_use]
    pub fn genesis(
        shard_id: ShardId,
        proposer: ValidatorId,
        state_root: StateRoot,
        origin: ChainOrigin,
    ) -> Self {
        let block = Block::genesis(shard_id, proposer, state_root, origin);
        let block_hash = block.hash();
        let base = QuorumCertificate::genesis(shard_id, origin);
        let qc_for_block = QuorumCertificate::new(
            block_hash,
            base.shard_id(),
            base.height(),
            base.parent_block_hash(),
            base.round(),
            base.signers().clone(),
            base.aggregated_signature(),
            base.weighted_timestamp(),
        );
        // SAFETY: genesis-shape QC paired with a freshly-built local
        // genesis block; both inputs are verified by construction
        // (empty-input root compute + zero-signers QC).
        let verified_block = Verified::<Block>::new_unchecked(block);
        let verified_qc = Verified::<QuorumCertificate>::new_unchecked(qc_for_block);
        Self::assemble(verified_block, verified_qc)
            .expect("genesis QC.block_hash == genesis block.hash() by construction")
    }

    /// Re-wrap a [`CertifiedBlock`] read out of persistent storage as
    /// verified.
    ///
    /// Certified blocks are persisted only after passing the full
    /// [`Verified<CertifiedBlock>`] predicate at admission (block
    /// per-root verifiers + QC sig + linkage), so re-reading them
    /// post-restart returns values whose predicate already held at
    /// write-time. The shard storage write entry point
    /// (`commit_block`) takes `&Arc<Verified<CertifiedBlock>>`, so
    /// unverified blocks can't reach the write path. Callers in
    /// storage adapters or recovery paths use this constructor; any
    /// other caller is misusing it.
    #[must_use]
    pub const fn from_persisted(certified: CertifiedBlock) -> Self {
        Self::new_unchecked(certified)
    }

    /// Pair a `Verified<Block>` with a `Verified<QuorumCertificate>`,
    /// checking the linkage invariant. Construction gate when this node
    /// ran the block's per-root verifiers locally.
    ///
    /// Construction asserts:
    /// 1. The block passes its full `Verified<Block>` predicate (header
    ///    verified, every applicable per-root verifier succeeded).
    /// 2. The QC passes its own verification predicate
    ///    (`Verified<QuorumCertificate>`).
    /// 3. `qc.block_hash == block.hash()` (structural pairing).
    ///
    /// See [`Self::from_qc_attestation`] for the alternate construction
    /// gate when per-root verification was performed by an external
    /// committee whose QC certifies the block.
    ///
    /// State-root verification is tracked separately in the verification
    /// pipeline and gates voting/commit via the parallel path, but is
    /// not folded into this type's predicate — see the doc on
    /// `Verified<Block>::assemble`.
    ///
    /// # Errors
    ///
    /// Returns [`LinkageError::BlockHashMismatch`] when `qc.block_hash`
    /// does not equal `block.hash()`.
    pub fn assemble(
        block: Verified<Block>,
        qc: Verified<QuorumCertificate>,
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
        Ok(Self::new_unchecked(CertifiedBlock {
            block,
            qc: qc.into(),
        }))
    }

    /// Construct from a raw `CertifiedBlock` paired with a verified QC,
    /// trusting the QC's signers to have run the block's per-root
    /// verifiers at their committee. Construction gate for sync-applied
    /// blocks and any other path where this node skips local per-root
    /// verification because the QC's BFT majority already attested.
    ///
    /// Construction asserts:
    /// 1. The QC passes its own verification predicate.
    /// 2. `qc.block_hash == certified.block().hash()`.
    /// 3. Every per-root verifier holds for the block — **not locally
    ///    re-run**. The trust source is the BFT property of the QC: at
    ///    least 2f+1 voters at the source committee verified each
    ///    per-root commitment before signing, so at least one honest
    ///    voter's check stands behind every claim.
    ///
    /// This constructor is the only path into `Verified<CertifiedBlock>`
    /// that exchanges local verification for an external attestation;
    /// every call site sits at a deliberate sync/admission boundary.
    /// Misuse — invoking this on a path where local verifiers WOULD
    /// have run and rejected — silently weakens the typestate to a
    /// BFT-transitive claim, so call sites carry a `// SAFETY:` comment
    /// naming the external-attestation source.
    ///
    /// # Errors
    ///
    /// Returns [`LinkageError::BlockHashMismatch`] when
    /// `qc.block_hash` does not equal `certified.block().hash()`.
    /// `CertifiedBlock` already enforces the pairing on its embedded
    /// QC, but this constructor *replaces* that embedded QC with the
    /// supplied verified one, so the linkage must be re-checked
    /// against the new QC.
    pub fn from_qc_attestation(
        certified: CertifiedBlock,
        qc: Verified<QuorumCertificate>,
    ) -> Result<Self, LinkageError> {
        let block_hash = certified.block().hash();
        let qc_block_hash = qc.block_hash();
        if qc_block_hash != block_hash {
            return Err(LinkageError::BlockHashMismatch {
                block_hash,
                qc_block_hash,
            });
        }
        let CertifiedBlock { block, qc: _ } = certified;
        Ok(Self::new_unchecked(CertifiedBlock {
            block,
            qc: qc.into(),
        }))
    }

    /// Borrow the verified QC. Total by the [`Verified<CertifiedBlock>`]
    /// predicate, which stores a [`Verifiable::Verified`] QC at
    /// assembly time.
    ///
    /// # Panics
    ///
    /// Panics if the embedded QC is `Unverified` — only reachable
    /// through a misuse of [`Verified::new_unchecked`].
    #[must_use]
    pub fn qc_verified(&self) -> &Verified<QuorumCertificate> {
        self.qc_verifiable()
            .verified()
            .expect("Verified<CertifiedBlock> predicate guarantees qc is Verified")
    }

    /// Synthesize a verified `parent_qc` via the BFT-transitive trust of
    /// this descendant's verified QC.
    ///
    /// The descendant's QC signs over `block.hash()`, which is derived
    /// from header content that includes the `parent_qc` field. The
    /// `Verified<CertifiedBlock>` predicate asserts at least 2f+1 of the
    /// source committee signed that bundle, so at least one honest
    /// signer verified `parent_qc` before voting. Same trust shape as
    /// [`Self::from_qc_attestation`] but applied to the embedded parent
    /// rather than the block-level QC.
    ///
    /// Returns the wrapped `parent_qc` regardless of whether it's
    /// genesis or signed — for genesis the result is byte-equal to
    /// [`Verified::<QuorumCertificate>::genesis`] for the same shard.
    /// Callers wanting only the signed case should pre-check
    /// `parent_qc().is_genesis()`.
    #[must_use]
    pub fn parent_qc_attested(&self) -> Verified<QuorumCertificate> {
        // SAFETY: the descendant's verified QC's signers attested to the
        // descendant's block content, which binds `parent_qc` by hash.
        // At least one honest signer ran the parent QC verifier before
        // voting; BFT-transitive trust.
        Verified::<QuorumCertificate>::new_unchecked(self.block().header().parent_qc().clone())
    }

    /// Project to the verified certified header — the block's header
    /// paired with its verified QC. Infallible: the
    /// [`Verified<CertifiedBlock>`] predicate already guarantees the QC
    /// commits this block's header, so the
    /// [`Verified<CertifiedBlockHeader>`] pairing holds by construction.
    #[must_use]
    pub fn certified_header(&self) -> Verified<CertifiedBlockHeader> {
        Verified::new_unchecked(CertifiedBlockHeader::new(
            self.block().header().clone(),
            self.qc_verified().clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use sbor::basic_encode;

    use super::*;
    use crate::{
        Round, ShardId, SignerBitfield, StateRoot, ValidatorId, WeightedTimestamp,
        zero_bls_signature,
    };

    /// A [`CertifiedBlock`]'s SBOR encoding does not depend on whether its
    /// QC is wrapped as [`Verifiable::Unverified`] or [`Verifiable::Verified`].
    /// This is the invariant that keeps wire bytes (and every merkle root or
    /// signature computed over them) stable across the field's type change
    /// from raw `QuorumCertificate` to `Verifiable<QuorumCertificate>`.
    #[test]
    fn wire_bypass_identical_across_verified_states() {
        let block = Block::genesis(
            ShardId::leaf(1, 0),
            ValidatorId::new(0),
            StateRoot::ZERO,
            ChainOrigin::ROOT,
        );
        let qc = QuorumCertificate::new(
            block.hash(),
            ShardId::leaf(1, 0),
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );

        let unverified = CertifiedBlock::new_unchecked(block.clone(), qc.clone());
        let verified =
            CertifiedBlock::new_unchecked(block, Verified::<QuorumCertificate>::new_unchecked(qc));

        let bytes_unverified = basic_encode(&unverified).unwrap();
        let bytes_verified = basic_encode(&verified).unwrap();
        assert_eq!(bytes_unverified, bytes_verified);
    }

    /// `from_qc_attestation` produces a `Verified<CertifiedBlock>` when the
    /// QC's `block_hash` matches the paired block, and rejects mismatches
    /// with the same `LinkageError` shape as `assemble`.
    #[test]
    fn from_qc_attestation_accepts_matching_pair_and_rejects_mismatch() {
        let block = Block::genesis(
            ShardId::leaf(1, 0),
            ValidatorId::new(0),
            StateRoot::ZERO,
            ChainOrigin::ROOT,
        );
        let block_hash = block.hash();
        let qc = QuorumCertificate::new(
            block_hash,
            ShardId::leaf(1, 0),
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );
        // SAFETY: synthetic test fixture.
        let verified_qc = Verified::<QuorumCertificate>::new_unchecked(qc.clone());

        let cb = CertifiedBlock::new_unchecked(block.clone(), qc.clone());
        let verified_cb = Verified::<CertifiedBlock>::from_qc_attestation(cb, verified_qc)
            .expect("matching block_hash succeeds");
        assert_eq!(verified_cb.qc_verified().block_hash(), block_hash);

        // Mismatched pair: pass a verified QC whose `block_hash` points
        // somewhere other than the certified block's hash. The
        // `CertifiedBlock` pairing invariant is satisfied internally
        // (its embedded QC matches its block), but `from_qc_attestation`
        // replaces the embedded QC with the supplied one, so it must
        // re-check the linkage against the new QC.
        let other_block = Block::genesis(
            ShardId::leaf(1, 1),
            ValidatorId::new(1),
            StateRoot::ZERO,
            ChainOrigin::ROOT,
        );
        let other_qc_raw = QuorumCertificate::new(
            other_block.hash(),
            ShardId::leaf(1, 1),
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );
        // SAFETY: synthetic test fixture.
        let other_verified_qc = Verified::<QuorumCertificate>::new_unchecked(other_qc_raw);
        let original_cb = CertifiedBlock::new_unchecked(block, qc);
        let err = Verified::<CertifiedBlock>::from_qc_attestation(original_cb, other_verified_qc)
            .expect_err("supplied QC's block_hash doesn't match the certified block");
        assert!(matches!(err, LinkageError::BlockHashMismatch { .. }));
    }

    /// `parent_qc_attested` returns the descendant's `parent_qc` wrapped as
    /// verified — byte-equal to whatever the header carries.
    #[test]
    fn parent_qc_attested_returns_header_parent_qc() {
        let block = Block::genesis(
            ShardId::leaf(1, 0),
            ValidatorId::new(0),
            StateRoot::ZERO,
            ChainOrigin::ROOT,
        );
        let block_hash = block.hash();
        let raw_qc = QuorumCertificate::genesis(ShardId::leaf(1, 0), ChainOrigin::ROOT);
        let qc_for_block = QuorumCertificate::new(
            block_hash,
            raw_qc.shard_id(),
            raw_qc.height(),
            raw_qc.parent_block_hash(),
            raw_qc.round(),
            raw_qc.signers().clone(),
            raw_qc.aggregated_signature(),
            raw_qc.weighted_timestamp(),
        );
        // SAFETY: synthetic test fixture, no real signature.
        let verified_qc = Verified::<QuorumCertificate>::new_unchecked(qc_for_block);

        let cb = CertifiedBlock {
            block: block.clone(),
            qc: verified_qc.into(),
        };
        let verified_cb = Verified::<CertifiedBlock>::new_unchecked(cb);

        let attested = verified_cb.parent_qc_attested();
        assert_eq!(attested.as_ref(), block.header().parent_qc());
    }
}
