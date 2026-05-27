//! Shard consensus block vote.
//!
//! [`BlockVote`] is the raw wire form. [`VerifiedBlockVote`] is the
//! verified typestate — constructed only via
//! [`<BlockVote as Verify>::verify`](Verify::verify) or
//! [`VerifiedBlockVote::new_unchecked`].
//!
//! Construction asserts: the BLS signature on the vote validates against
//! the voter's public key for the domain-separated signing message
//! `block_vote_message(network, shard, height, round, block_hash)`.

use std::ops::Deref;

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeight, Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature,
    NetworkDefinition, ProposerTimestamp, Round, ShardGroupId, ValidatorId, Verifiable, Verify,
    block_vote_message, verify_bls12381_v1,
};

/// Block vote for shard consensus.
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
    #[allow(clippy::too_many_arguments)] // mirrors the 7 stored fields plus the network identity
    pub fn new(
        network: &NetworkDefinition,
        block_hash: BlockHash,
        shard_group_id: ShardGroupId,
        height: BlockHeight,
        round: Round,
        voter: ValidatorId,
        signing_key: &Bls12381G1PrivateKey,
        timestamp: ProposerTimestamp,
    ) -> Self {
        let message = block_vote_message(network, shard_group_id, height, round, &block_hash);
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
    pub fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        block_vote_message(
            network,
            self.shard_group_id,
            self.height,
            self.round,
            &self.block_hash,
        )
    }
}

/// Inputs the [`BlockVote`] verifier reads against. Borrows everything;
/// nothing is consumed.
#[derive(Debug, Clone, Copy)]
pub struct BlockVoteContext<'a> {
    /// Network identifier — feeds the domain-separated signing message.
    pub network: &'a NetworkDefinition,
    /// BLS public key of the voter who cast this vote.
    pub voter_public_key: &'a Bls12381G1PublicKey,
}

/// Failure modes of [`BlockVote`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BlockVoteVerifyError {
    /// The BLS signature did not validate against the voter's public key
    /// for the vote's domain-separated signing message.
    #[error("BLS signature invalid")]
    InvalidSignature,
}

/// Verified block vote.
///
/// The construction predicate is stated in the module docs. Construction
/// goes through one of two gates:
///
/// - [`<BlockVote as Verify>::verify`](Verify::verify) — runs the BLS
///   signature check against the voter's public key.
/// - [`Self::new_unchecked`] — audit point. Used by batch verification
///   helpers that ran the same predicate (typically same-message BLS
///   batch verify) over a slice and re-wrap each element under the
///   batch's trust source, and by own-vote paths where the local signer
///   just produced the signature. Every call site documents the trust
///   source with a `// SAFETY:` comment.
///
/// Read-only: [`Deref<Target = BlockVote>`](Deref) exposes the raw
/// vote's accessors. No `&mut`, no `AsMut`, no `Encode`/`Decode` —
/// verified values cannot be produced from wire bytes.
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBlockVote(BlockVote);

impl VerifiedBlockVote {
    /// Audit-point constructor. Skips the predicate.
    ///
    /// Permitted use sites: batch verification helpers that ran an
    /// equivalent same-message BLS check over multiple votes, and the
    /// own-vote signing path where the local validator produced the
    /// signature in this process. Every call site carries a
    /// `// SAFETY:` comment naming the trust source.
    #[must_use]
    pub const fn new_unchecked(vote: BlockVote) -> Self {
        Self(vote)
    }

    /// Consume the verified vote and return the raw form. Drops the
    /// verified claim.
    #[must_use]
    pub const fn into_inner(self) -> BlockVote {
        self.0
    }
}

impl AsRef<BlockVote> for VerifiedBlockVote {
    fn as_ref(&self) -> &BlockVote {
        &self.0
    }
}

impl Deref for VerifiedBlockVote {
    type Target = BlockVote;
    fn deref(&self) -> &BlockVote {
        &self.0
    }
}

impl From<VerifiedBlockVote> for BlockVote {
    fn from(verified: VerifiedBlockVote) -> Self {
        verified.0
    }
}

impl From<VerifiedBlockVote> for Verifiable<BlockVote, VerifiedBlockVote> {
    fn from(verified: VerifiedBlockVote) -> Self {
        Self::Verified(verified)
    }
}

impl Verify<&BlockVoteContext<'_>> for BlockVote {
    type Verified = VerifiedBlockVote;
    type Error = BlockVoteVerifyError;

    fn verify(&self, ctx: &BlockVoteContext<'_>) -> Result<Self::Verified, Self::Error> {
        let message = self.signing_message(ctx.network);
        if !verify_bls12381_v1(&message, ctx.voter_public_key, &self.signature) {
            return Err(BlockVoteVerifyError::InvalidSignature);
        }
        Ok(VerifiedBlockVote(self.clone()))
    }
}
