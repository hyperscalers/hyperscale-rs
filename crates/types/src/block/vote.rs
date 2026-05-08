//! BFT block vote.

use sbor::prelude::*;

use crate::{
    BlockHash, BlockHeight, Bls12381G1PrivateKey, Bls12381G2Signature, ProposerTimestamp, Round,
    ShardGroupId, ValidatorId, block_vote_message,
};

/// Block vote for BFT consensus.
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct BlockVote {
    block_hash: BlockHash,
    shard_group_id: ShardGroupId,
    height: BlockHeight,
    round: Round,
    voter: ValidatorId,
    signature: Bls12381G2Signature,
    timestamp: ProposerTimestamp,
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

    /// Build a `BlockVote` from its parts without re-signing. Caller is
    /// responsible for the signature being valid for the other fields.
    #[must_use]
    pub const fn from_parts(
        block_hash: BlockHash,
        shard_group_id: ShardGroupId,
        height: BlockHeight,
        round: Round,
        voter: ValidatorId,
        signature: Bls12381G2Signature,
        timestamp: ProposerTimestamp,
    ) -> Self {
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

    /// Hash of the block being voted on.
    #[must_use]
    pub const fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    /// Shard group this vote belongs to (prevents cross-shard replay).
    #[must_use]
    pub const fn shard_group_id(&self) -> ShardGroupId {
        self.shard_group_id
    }

    /// Height of the block.
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.height
    }

    /// Round number (for view change).
    #[must_use]
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Validator who cast this vote.
    #[must_use]
    pub const fn voter(&self) -> ValidatorId {
        self.voter
    }

    /// BLS signature over the domain-separated signing message.
    #[must_use]
    pub const fn signature(&self) -> Bls12381G2Signature {
        self.signature
    }

    /// Voter's local wall-clock when this vote was created. Stake-weighted
    /// into the QC's `weighted_timestamp` once 2f+1 votes are aggregated.
    #[must_use]
    pub const fn timestamp(&self) -> ProposerTimestamp {
        self.timestamp
    }

    /// Decompose into the raw fields, in struct-declaration order.
    #[must_use]
    pub const fn into_parts(
        self,
    ) -> (
        BlockHash,
        ShardGroupId,
        BlockHeight,
        Round,
        ValidatorId,
        Bls12381G2Signature,
        ProposerTimestamp,
    ) {
        (
            self.block_hash,
            self.shard_group_id,
            self.height,
            self.round,
            self.voter,
            self.signature,
            self.timestamp,
        )
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
