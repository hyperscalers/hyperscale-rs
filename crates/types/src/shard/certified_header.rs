//! `CertifiedBlockHeader` — block header paired with the QC that committed it.
//!
//! [`CertifiedBlockHeader`] is the raw wire form. Its verified form is
//! `Verified<CertifiedBlockHeader>` — produced by BFT-transitive trust
//! ([`impl Verified<CertifiedBlockHeader>::from_qc_attestation`] — the
//! light-client trust path for remote-shard headers).

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeader, BlockHeight, QcVerifyError, QuorumCertificate, ShardGroupId, StateRoot,
    Verifiable, Verified,
};

/// Failure modes of [`CertifiedBlockHeader`] verification.
///
/// Combines QC-level failures with the linkage check that ties the QC to
/// its paired header. Variants surface through the
/// `RemoteHeaderQcVerified` event payload.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum CertifiedHeaderVerifyError {
    /// The QC failed its own verification predicate.
    #[error("QC verification failed: {0}")]
    Qc(#[from] QcVerifyError),
    /// The QC's `block_hash` does not match the paired header's
    /// computed hash. Indicates a malformed or adversarial pair.
    #[error("qc.block_hash does not match header.hash()")]
    LinkageMismatch,
}

/// A block header paired with the QC that committed it.
///
/// This is the minimal cross-shard trust attestation: given a `CertifiedBlockHeader`,
/// a remote shard can verify the QC against the source shard's validator public keys
/// (from topology), confirm the `block_hash` matches `hash(header)`, and then trust
/// the `state_root` in the header for merkle inclusion proof verification.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct CertifiedBlockHeader {
    header: BlockHeader,
    qc: Verifiable<QuorumCertificate>,
}

impl CertifiedBlockHeader {
    /// Create a new certified block header.
    #[must_use]
    pub fn new(header: BlockHeader, qc: impl Into<Verifiable<QuorumCertificate>>) -> Self {
        Self {
            header,
            qc: qc.into(),
        }
    }

    /// Header whose `hash()` matches the QC's `block_hash`.
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// QC committing [`Self::header`]; verifiable against the source shard's
    /// validator keys without access to the block body.
    #[must_use]
    pub fn qc(&self) -> &QuorumCertificate {
        self.qc.as_unverified()
    }

    /// Consume the pair and return its parts.
    #[must_use]
    pub fn into_parts(self) -> (BlockHeader, Verifiable<QuorumCertificate>) {
        (self.header, self.qc)
    }

    /// Compute the block hash (hashes the header).
    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// Get the block height.
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.header.height()
    }

    /// Get the shard group this block belongs to.
    #[must_use]
    pub const fn shard_group_id(&self) -> ShardGroupId {
        self.header.shard_group_id()
    }

    /// Get the state root committed by this block.
    #[must_use]
    pub const fn state_root(&self) -> StateRoot {
        self.header.state_root()
    }
}

impl Verified<CertifiedBlockHeader> {
    /// Construct from a raw header paired with a verified QC, trusting the
    /// QC's signers to have validated the header at their committee. The
    /// light-client construction gate: receivers of cross-shard committed
    /// headers don't re-run the source committee's per-root verifiers, so
    /// the `Verified<CertifiedBlockHeader>` predicate's "header verified"
    /// claim rests on the BFT property of the supplied QC rather than a
    /// local `Verified<BlockHeader>` witness.
    ///
    /// Construction asserts:
    /// 1. The QC passes its own verification predicate (witnessed by its
    ///    `Verified<QuorumCertificate>` type).
    /// 2. `qc.block_hash == header.hash()` — the QC commits exactly this
    ///    header.
    /// 3. The header's structural validity is asserted by the QC's
    ///    signers: at least 2f+1 of the source committee accepted the
    ///    header (and its `parent_qc`) before voting, so at least one
    ///    honest signer's checks stand behind the claim. This trust
    ///    source is parallel to
    ///    [`Verified::<CertifiedBlock>::from_qc_attestation`].
    ///
    /// Misuse — invoking this on a path where local header verification
    /// WOULD have run and rejected — silently weakens the typestate to a
    /// BFT-transitive claim, so call sites carry a `// SAFETY:` comment
    /// naming the attestation source.
    ///
    /// # Errors
    ///
    /// Returns [`CertifiedHeaderVerifyError::LinkageMismatch`] when
    /// `qc.block_hash() != header.hash()`.
    pub fn from_qc_attestation(
        header: BlockHeader,
        qc: Verified<QuorumCertificate>,
    ) -> Result<Self, CertifiedHeaderVerifyError> {
        if qc.block_hash() != header.hash() {
            return Err(CertifiedHeaderVerifyError::LinkageMismatch);
        }
        Ok(Self::new_unchecked(CertifiedBlockHeader {
            header,
            qc: qc.into(),
        }))
    }
}
