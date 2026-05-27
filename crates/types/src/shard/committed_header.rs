//! `CommittedBlockHeader` — block header paired with the QC that committed it.

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeader, BlockHeight, QcVerifyError, QuorumCertificate, ShardGroupId, StateRoot,
    Verifiable, VerifiedQuorumCertificate,
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
