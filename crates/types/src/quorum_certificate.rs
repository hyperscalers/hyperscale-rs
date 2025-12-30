//! Quorum certificate for BFT consensus.

use crate::{
    zero_bls_signature, BlockHeight, Bls12381G2Signature, Hash, SignerBitfield, VotePower,
};
use sbor::prelude::*;

/// A quorum certificate proving 2f+1 validators voted for a block.
///
/// Contains an aggregated BLS signature from the voting validators.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct QuorumCertificate {
    /// Hash of the block this QC certifies.
    pub block_hash: Hash,

    /// Height of the certified block.
    pub height: BlockHeight,

    /// Hash of the parent block (for two-chain commit rule).
    pub parent_block_hash: Hash,

    /// Round number when this QC was formed.
    pub round: u64,

    /// Bitfield indicating which validators signed.
    pub signers: SignerBitfield,

    /// Aggregated BLS signature from all signers.
    pub aggregated_signature: Bls12381G2Signature,

    /// Total voting power represented by this QC.
    pub voting_power: VotePower,

    /// Stake-weighted timestamp in milliseconds.
    /// Computed as: sum(timestamp_i * stake_i) / sum(stake_i)
    pub weighted_timestamp_ms: u64,
}

impl QuorumCertificate {
    /// Create a genesis QC (for block 0).
    ///
    /// The genesis QC has a zero block hash and zero signature.
    pub fn genesis() -> Self {
        Self {
            block_hash: Hash::ZERO,
            height: BlockHeight(0),
            parent_block_hash: Hash::ZERO,
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(0),
            weighted_timestamp_ms: 0,
        }
    }

    /// Check if this is a genesis QC.
    pub fn is_genesis(&self) -> bool {
        self.height.0 == 0 && self.block_hash == Hash::ZERO
    }

    /// Get the number of signers.
    pub fn signer_count(&self) -> usize {
        self.signers.count_ones()
    }

    /// Check if this QC has quorum (> 2/3 voting power).
    pub fn has_quorum(&self, total_power: u64) -> bool {
        VotePower::has_quorum(self.voting_power.0, total_power)
    }

    /// Two-chain commit rule: Check if this QC enables committing the parent block.
    ///
    /// A QC for block at height N allows committing the block at height N-1.
    /// Genesis QC (height 0) doesn't enable any commit.
    pub fn has_committable_block(&self) -> bool {
        self.height.0 > 0 && !self.is_genesis()
    }

    /// Get the height of the committable block (parent height).
    ///
    /// Returns None for genesis QC.
    pub fn committable_height(&self) -> Option<BlockHeight> {
        if self.has_committable_block() {
            Some(BlockHeight(self.height.0 - 1))
        } else {
            None
        }
    }

    /// Get the hash of the committable block (parent hash).
    ///
    /// Returns None for genesis QC.
    pub fn committable_hash(&self) -> Option<Hash> {
        if self.has_committable_block() {
            Some(self.parent_block_hash)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_qc() {
        let qc = QuorumCertificate::genesis();
        assert!(qc.is_genesis());
        assert_eq!(qc.height, BlockHeight(0));
        assert_eq!(qc.block_hash, Hash::ZERO);
        assert_eq!(qc.signer_count(), 0);
        assert!(!qc.has_committable_block());
        assert!(qc.committable_height().is_none());
        assert!(qc.committable_hash().is_none());
    }

    #[test]
    fn test_non_genesis_qc() {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);

        let parent_hash = Hash::from_bytes(b"parent");
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block1"),
            height: BlockHeight(1),
            parent_block_hash: parent_hash,
            round: 0,
            signers,
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 1000,
        };

        assert!(!qc.is_genesis());
        assert_eq!(qc.signer_count(), 3);
        assert!(qc.has_committable_block());
        assert_eq!(qc.committable_height(), Some(BlockHeight(0)));
        assert_eq!(qc.committable_hash(), Some(parent_hash));
        assert!(qc.has_quorum(4)); // 3/4 > 2/3
        assert!(!qc.has_quorum(5)); // 3/5 < 2/3
    }
}
