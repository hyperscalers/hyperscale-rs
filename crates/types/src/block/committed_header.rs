//! `CommittedBlockHeader` — block header paired with the QC that committed it.

use crate::{BlockHash, BlockHeader, BlockHeight, QuorumCertificate, ShardGroupId, StateRoot};
use sbor::prelude::*;

/// A block header paired with the QC that committed it.
///
/// This is the minimal cross-shard trust attestation: given a `CommittedBlockHeader`,
/// a remote shard can verify the QC against the source shard's validator public keys
/// (from topology), confirm the `block_hash` matches `hash(header)`, and then trust
/// the `state_root` in the header for merkle inclusion proof verification.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct CommittedBlockHeader {
    /// The block header.
    pub header: BlockHeader,

    /// The quorum certificate that committed this block.
    pub qc: QuorumCertificate,
}

impl CommittedBlockHeader {
    /// Create a new committed block header.
    #[must_use]
    pub fn new(header: BlockHeader, qc: QuorumCertificate) -> Self {
        Self { header, qc }
    }

    /// Compute the block hash (hashes the header).
    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// Get the block height.
    #[must_use]
    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Get the shard group this block belongs to.
    #[must_use]
    pub fn shard_group_id(&self) -> ShardGroupId {
        self.header.shard_group_id
    }

    /// Get the state root committed by this block.
    #[must_use]
    pub fn state_root(&self) -> StateRoot {
        self.header.state_root
    }
}
