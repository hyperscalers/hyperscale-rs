//! `CommittedBlockHeader` — block header paired with the QC that committed it.

use sbor::prelude::*;

use crate::{BlockHash, BlockHeader, BlockHeight, QuorumCertificate, ShardGroupId, StateRoot};

/// A block header paired with the QC that committed it.
///
/// This is the minimal cross-shard trust attestation: given a `CommittedBlockHeader`,
/// a remote shard can verify the QC against the source shard's validator public keys
/// (from topology), confirm the `block_hash` matches `hash(header)`, and then trust
/// the `state_root` in the header for merkle inclusion proof verification.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct CommittedBlockHeader {
    header: BlockHeader,
    qc: QuorumCertificate,
}

impl CommittedBlockHeader {
    /// Create a new committed block header.
    #[must_use]
    pub const fn new(header: BlockHeader, qc: QuorumCertificate) -> Self {
        Self { header, qc }
    }

    /// Header whose `hash()` matches the QC's `block_hash`.
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// QC committing [`Self::header`]; verifiable against the source shard's
    /// validator keys without access to the block body.
    #[must_use]
    pub const fn qc(&self) -> &QuorumCertificate {
        &self.qc
    }

    /// Consume the pair and return its parts.
    #[must_use]
    pub fn into_parts(self) -> (BlockHeader, QuorumCertificate) {
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
        self.header.height
    }

    /// Get the shard group this block belongs to.
    #[must_use]
    pub const fn shard_group_id(&self) -> ShardGroupId {
        self.header.shard_group_id
    }

    /// Get the state root committed by this block.
    #[must_use]
    pub const fn state_root(&self) -> StateRoot {
        self.header.state_root
    }
}
