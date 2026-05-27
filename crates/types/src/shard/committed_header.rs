//! `CommittedBlockHeader` — block header paired with the QC that committed it.
//!
//! [`CommittedBlockHeader`] is the raw wire form.
//! [`VerifiedCommittedBlockHeader`] is the verified composite typestate:
//! header verified + QC verified + `qc.block_hash == header.hash()`.

use std::ops::Deref;

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeader, BlockHeight, QcVerifyError, QuorumCertificate, ShardGroupId, StateRoot,
    Verifiable, VerifiedBlockHeader, VerifiedQuorumCertificate,
};

/// Failure modes of [`CommittedBlockHeader`] verification.
///
/// Combines QC-level failures with the linkage check that ties the QC to
/// its paired header. Variants surface through the
/// `RemoteHeaderQcVerified` event payload.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum CommittedHeaderVerifyError {
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
/// This is the minimal cross-shard trust attestation: given a `CommittedBlockHeader`,
/// a remote shard can verify the QC against the source shard's validator public keys
/// (from topology), confirm the `block_hash` matches `hash(header)`, and then trust
/// the `state_root` in the header for merkle inclusion proof verification.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct CommittedBlockHeader {
    header: BlockHeader,
    qc: Verifiable<QuorumCertificate, VerifiedQuorumCertificate>,
}

impl CommittedBlockHeader {
    /// Create a new committed block header.
    #[must_use]
    pub fn new(
        header: BlockHeader,
        qc: impl Into<Verifiable<QuorumCertificate, VerifiedQuorumCertificate>>,
    ) -> Self {
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
    pub fn into_parts(
        self,
    ) -> (
        BlockHeader,
        Verifiable<QuorumCertificate, VerifiedQuorumCertificate>,
    ) {
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

/// Verified [`CommittedBlockHeader`].
///
/// Construction asserts:
/// 1. The header passes [`<BlockHeader as crate::Verify>`](crate::Verify)
///    (so its `parent_qc` is verified).
/// 2. The QC pairing this committed-header was verified against the
///    source-shard committee.
/// 3. The QC's `block_hash` equals `header.hash()` — the QC commits
///    exactly this header.
///
/// Construction goes through [`Self::assemble`] (composite path that
/// runs the linkage check) or [`Self::new_unchecked`] (audit point).
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCommittedBlockHeader(CommittedBlockHeader);

impl VerifiedCommittedBlockHeader {
    /// Composite assembly. Pairs a [`VerifiedBlockHeader`] with a
    /// [`VerifiedQuorumCertificate`] after confirming the QC's
    /// `block_hash` matches `header.hash()`.
    ///
    /// # Errors
    ///
    /// Returns [`CommittedHeaderVerifyError::LinkageMismatch`] when
    /// `qc.block_hash() != header.hash()`.
    pub fn assemble(
        header: VerifiedBlockHeader,
        qc: VerifiedQuorumCertificate,
    ) -> Result<Self, CommittedHeaderVerifyError> {
        if qc.block_hash() != header.as_ref().hash() {
            return Err(CommittedHeaderVerifyError::LinkageMismatch);
        }
        let header = header.into_inner();
        Ok(Self(CommittedBlockHeader {
            header,
            qc: Verifiable::Verified(qc),
        }))
    }

    /// Audit-point constructor. Skips the predicate.
    ///
    /// Permitted use sites: storage-recovery (header+QC were verified
    /// before persistence) and call sites that established the
    /// predicate by other means. Every call site carries a `// SAFETY:`
    /// comment naming the trust source.
    #[must_use]
    pub const fn new_unchecked(inner: CommittedBlockHeader) -> Self {
        Self(inner)
    }

    /// Borrow the underlying [`CommittedBlockHeader`].
    #[must_use]
    pub const fn as_committed(&self) -> &CommittedBlockHeader {
        &self.0
    }

    /// Consume the wrapper and return the raw [`CommittedBlockHeader`].
    #[must_use]
    pub fn into_inner(self) -> CommittedBlockHeader {
        self.0
    }
}

impl AsRef<CommittedBlockHeader> for VerifiedCommittedBlockHeader {
    fn as_ref(&self) -> &CommittedBlockHeader {
        &self.0
    }
}

impl Deref for VerifiedCommittedBlockHeader {
    type Target = CommittedBlockHeader;
    fn deref(&self) -> &CommittedBlockHeader {
        &self.0
    }
}

impl From<VerifiedCommittedBlockHeader> for CommittedBlockHeader {
    fn from(verified: VerifiedCommittedBlockHeader) -> Self {
        verified.0
    }
}
