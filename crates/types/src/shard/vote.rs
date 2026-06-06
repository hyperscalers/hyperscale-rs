//! Shard consensus block vote.
//!
//! [`BlockVote`] is the raw wire form. Its verified form is
//! `Verified<BlockVote>`; predicate at
//! [`impl Verify<&BlockVoteContext<'_>>`](Verify::verify) below.

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeight, Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature,
    NetworkDefinition, ProposerTimestamp, Round, ShardGroupId, ValidatorId, Verified, Verify,
    batch_verify_bls_same_message, block_vote_message, verify_bls12381_v1,
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
        parent_block_hash: BlockHash,
        shard_group_id: ShardGroupId,
        height: BlockHeight,
        round: Round,
        voter: ValidatorId,
        signing_key: &Bls12381G1PrivateKey,
        timestamp: ProposerTimestamp,
    ) -> Self {
        let message = block_vote_message(
            network,
            shard_group_id,
            height,
            round,
            &block_hash,
            &parent_block_hash,
        );
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
    ///
    /// `parent_block_hash` isn't stored on the vote; the verifier supplies it
    /// (from the block header, or the QC's own field for an aggregate).
    #[must_use]
    pub fn signing_message(
        &self,
        network: &NetworkDefinition,
        parent_block_hash: &BlockHash,
    ) -> Vec<u8> {
        block_vote_message(
            network,
            self.shard_group_id,
            self.height,
            self.round,
            &self.block_hash,
            parent_block_hash,
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
    /// Parent of the voted block (from its header), bound into the signing message.
    pub parent_block_hash: BlockHash,
}

/// Failure modes of [`BlockVote`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BlockVoteVerifyError {
    /// The BLS signature did not validate against the voter's public key
    /// for the vote's domain-separated signing message.
    #[error("BLS signature invalid")]
    InvalidSignature,
}

/// Construction asserts: the BLS signature on the vote validates against
/// the voter's public key for the domain-separated signing message
/// `block_vote_message(network, shard, height, round, block_hash)`.
///
/// Construction goes through one of three gates:
///
/// - [`<BlockVote as Verify>::verify`](Verify::verify) — runs the BLS
///   signature check against the voter's public key.
/// - [`Verified::<BlockVote>::verify_batch`] — runs the same predicate
///   over a slice using the BLS same-message batch optimisation, with
///   individual-verify fallback when the batch fails.
/// - [`Verified::<BlockVote>::sign_local`] — signs a fresh vote with
///   the caller's key; the act of signing is the predicate witness.
impl Verify<&BlockVoteContext<'_>> for BlockVote {
    type Error = BlockVoteVerifyError;

    fn verify(&self, ctx: &BlockVoteContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let message = self.signing_message(ctx.network, &ctx.parent_block_hash);
        if !verify_bls12381_v1(&message, ctx.voter_public_key, &self.signature) {
            return Err(BlockVoteVerifyError::InvalidSignature);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<BlockVote> {
    /// Sign a fresh [`BlockVote`] with `signing_key` and return its
    /// verified form.
    ///
    /// The predicate holds by construction: the BLS signature over the
    /// canonical `block_vote_message` is produced from `signing_key`
    /// inside this call, so any later
    /// [`<BlockVote as Verify>::verify`](Verify::verify) call against
    /// the matching public key would succeed. Used at proposer/voter
    /// sites that need the verified value immediately for local-fast-
    /// path consumers (e.g. echoing the signed vote back to the local
    /// [`VoteSet`](crate::Verified)).
    #[must_use]
    #[allow(clippy::too_many_arguments)] // mirrors the 7 stored fields plus the network identity
    pub fn sign_local(
        network: &NetworkDefinition,
        block_hash: BlockHash,
        parent_block_hash: BlockHash,
        shard_group_id: ShardGroupId,
        height: BlockHeight,
        round: Round,
        voter: ValidatorId,
        signing_key: &Bls12381G1PrivateKey,
        timestamp: ProposerTimestamp,
    ) -> Self {
        // SAFETY: the BLS signature is produced by `signing_key` over
        // the canonical `block_vote_message`, which is exactly the
        // `BlockVote::verify` predicate's check against this voter's
        // matching pubkey.
        Self::new_unchecked(BlockVote::new(
            network,
            block_hash,
            parent_block_hash,
            shard_group_id,
            height,
            round,
            voter,
            signing_key,
            timestamp,
        ))
    }

    /// Verify a slice of `(vote, pubkey)` pairs against a single
    /// `signing_message` using the BLS same-message batch optimisation.
    ///
    /// Every vote in the batch must have been signed over `signing_message`
    /// (the canonical [`block_vote_message`] for some `block_hash`,
    /// `height`, `round`, `shard_group_id`). The caller is responsible
    /// for assembling the batch with matching messages — mismatched
    /// votes will simply fail to verify.
    ///
    /// On batch failure the implementation falls back to individual
    /// [`Verify::verify`] calls so a single forged signature doesn't
    /// poison the whole batch. Each output position mirrors its input
    /// position: `Some(verified)` for votes that passed, `None` for
    /// votes whose signature didn't validate.
    #[must_use]
    pub fn verify_batch(
        signing_message: &[u8],
        votes: Vec<(BlockVote, Bls12381G1PublicKey)>,
    ) -> Vec<Option<Self>> {
        if votes.is_empty() {
            return Vec::new();
        }

        let signatures: Vec<Bls12381G2Signature> =
            votes.iter().map(|(v, _)| v.signature()).collect();
        let public_keys: Vec<Bls12381G1PublicKey> = votes.iter().map(|(_, pk)| *pk).collect();

        if batch_verify_bls_same_message(signing_message, &signatures, &public_keys) {
            // SAFETY: BLS same-message batch verify just confirmed every
            // signature in this batch against its paired public key over
            // `signing_message`, which is exactly the `BlockVote::verify`
            // predicate (the caller's contract is to pass votes that
            // share that signing message).
            return votes
                .into_iter()
                .map(|(vote, _)| Some(Self::new_unchecked(vote)))
                .collect();
        }

        votes
            .into_iter()
            .map(|(vote, pk)| {
                if verify_bls12381_v1(signing_message, &pk, &vote.signature()) {
                    // SAFETY: individual BLS verify just re-ran the
                    // `BlockVote::verify` predicate against the voter's
                    // pubkey.
                    Some(Self::new_unchecked(vote))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash, generate_bls_keypair};

    /// All-valid batch verifies via the fast path and yields one
    /// `Some(verified)` per input position.
    #[test]
    fn verify_batch_all_valid_returns_all_verified() {
        let net = NetworkDefinition::simulator();
        let message = block_vote_message(
            &net,
            ShardGroupId::ROOT,
            BlockHeight::new(1),
            Round::INITIAL,
            &BlockHash::from_raw(Hash::from_bytes(&[1u8; 32])),
            &BlockHash::from_raw(Hash::from_bytes(b"parent")),
        );
        let votes: Vec<_> = (0..3)
            .map(|i| {
                let sk = generate_bls_keypair();
                let signature = sk.sign_v1(&message);
                let pk = sk.public_key();
                let vote = BlockVote::from_parts(
                    BlockHash::from_raw(Hash::from_bytes(&[1u8; 32])),
                    ShardGroupId::ROOT,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    ValidatorId::new(i),
                    signature,
                    ProposerTimestamp::ZERO,
                );
                (vote, pk)
            })
            .collect();

        let results = Verified::<BlockVote>::verify_batch(&message, votes);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(Option::is_some));
    }

    /// One forged signature in the batch triggers the per-vote fallback;
    /// every honest vote still surfaces verified, the forged position
    /// surfaces `None`.
    #[test]
    fn verify_batch_falls_back_and_drops_only_the_forged_vote() {
        let net = NetworkDefinition::simulator();
        let message = block_vote_message(
            &net,
            ShardGroupId::ROOT,
            BlockHeight::new(1),
            Round::INITIAL,
            &BlockHash::from_raw(Hash::from_bytes(&[2u8; 32])),
            &BlockHash::from_raw(Hash::from_bytes(b"parent")),
        );
        let mut votes: Vec<(BlockVote, Bls12381G1PublicKey)> = Vec::new();
        for i in 0..3u64 {
            let sk = generate_bls_keypair();
            let signature = sk.sign_v1(&message);
            let pk = sk.public_key();
            let vote = BlockVote::from_parts(
                BlockHash::from_raw(Hash::from_bytes(&[2u8; 32])),
                ShardGroupId::ROOT,
                BlockHeight::new(1),
                Round::INITIAL,
                ValidatorId::new(i),
                signature,
                ProposerTimestamp::ZERO,
            );
            votes.push((vote, pk));
        }

        // Replace the middle vote's pubkey with a fresh unrelated one so the
        // signature no longer validates.
        let intruder_sk = generate_bls_keypair();
        votes[1].1 = intruder_sk.public_key();

        let results = Verified::<BlockVote>::verify_batch(&message, votes);
        assert_eq!(results.len(), 3);
        assert!(results[0].is_some());
        assert!(results[1].is_none());
        assert!(results[2].is_some());
    }

    /// Empty input produces an empty output (no allocation, no fallback).
    #[test]
    fn verify_batch_empty_input_returns_empty() {
        let results = Verified::<BlockVote>::verify_batch(b"unused", Vec::new());
        assert!(results.is_empty());
    }
}
