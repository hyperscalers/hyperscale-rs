//! BFT block vote.

use crate::{
    BlockHash, BlockHeight, Bls12381G1PrivateKey, Bls12381G2Signature, ProposerTimestamp, Round,
    ShardGroupId, ValidatorId, block_vote_message,
};
use sbor::prelude::*;

/// Block vote for BFT consensus.
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct BlockVote {
    /// Hash of the block being voted on.
    pub block_hash: BlockHash,
    /// Shard group this vote belongs to (prevents cross-shard replay).
    pub shard_group_id: ShardGroupId,
    /// Height of the block.
    pub height: BlockHeight,
    /// Round number (for view change).
    pub round: Round,
    /// Validator who cast this vote.
    pub voter: ValidatorId,
    /// BLS signature over the domain-separated signing message.
    pub signature: Bls12381G2Signature,
    /// Voter's local wall-clock when this vote was created. Stake-weighted
    /// into the QC's `weighted_timestamp` once 2f+1 votes are aggregated.
    pub timestamp: ProposerTimestamp,
}

impl BlockVote {
    /// Create a new block vote with domain-separated signing.
    #[must_use]
    pub fn new(
        block_hash: BlockHash,
        shard_group_id: ShardGroupId,
        height: BlockHeight,
        round: Round,
        voter: ValidatorId,
        signing_key: &Bls12381G1PrivateKey,
        timestamp: ProposerTimestamp,
    ) -> Self {
        let message = block_vote_message(shard_group_id, height, round, &block_hash);
        let signature = signing_key.sign_v1(&message);
        Self {
            block_hash,
            shard_group_id,
            height,
            round,
            voter,
            signature,
            timestamp,
        }
    }

    /// Build the canonical signing message for this vote.
    ///
    /// Uses `DOMAIN_BLOCK_VOTE` tag for domain separation.
    /// This is the same message used for QC aggregated signature verification.
    #[must_use]
    pub fn signing_message(&self) -> Vec<u8> {
        block_vote_message(
            self.shard_group_id,
            self.height,
            self.round,
            &self.block_hash,
        )
    }
}
