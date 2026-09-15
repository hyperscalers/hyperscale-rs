//! Shard consensus block vote.
//!
//! [`BlockVote`] is the raw wire form. Its verified form is
//! `Verified<BlockVote>`; predicate at
//! [`impl Verify<&BlockVoteContext<'_>>`](Verify::verify) below.

use hyperscale_crypto::{SignError, Signer, Verifier};
use hyperscale_hbor::Hbor;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeight, BlockVoteMessage, ConsensusPublicKey, ConsensusSignature,
    NetworkDefinition, ProposerTimestamp, Round, ShardId, ValidatorId, Verified, Verify,
    signed_bytes,
};

/// Block vote for shard consensus.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct BlockVote {
    block_hash: BlockHash,
    shard_id: ShardId,
    height: BlockHeight,
    round: Round,
    voter: ValidatorId,
    signature: ConsensusSignature,
    timestamp: ProposerTimestamp,
}

impl BlockVote {
    /// Create a new block vote with domain-separated signing.
    ///
    /// # Errors
    ///
    /// Propagates [`SignError`] when the signer cannot sign.
    #[allow(clippy::too_many_arguments)] // mirrors the 7 stored fields plus the network identity
    pub fn new(
        network: &NetworkDefinition,
        block_hash: BlockHash,
        parent_block_hash: BlockHash,
        shard_id: ShardId,
        height: BlockHeight,
        round: Round,
        voter: ValidatorId,
        signer: &dyn Signer,
        timestamp: ProposerTimestamp,
    ) -> Result<Self, SignError> {
        let message = signed_bytes(
            &BlockVoteMessage {
                shard_group: shard_id,
                height,
                round,
                block_hash,
                parent_block_hash,
            },
            network,
        );
        let signature = signer.sign(&message)?;
        Ok(Self {
            block_hash,
            shard_id,
            height,
            round,
            voter,
            signature,
            timestamp,
        })
    }

    /// Build a `BlockVote` from its parts without re-signing. Caller is
    /// responsible for the signature being valid for the other fields.
    #[must_use]
    pub const fn from_parts(
        block_hash: BlockHash,
        shard_id: ShardId,
        height: BlockHeight,
        round: Round,
        voter: ValidatorId,
        signature: ConsensusSignature,
        timestamp: ProposerTimestamp,
    ) -> Self {
        Self {
            block_hash,
            shard_id,
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
    pub const fn shard_id(&self) -> ShardId {
        self.shard_id
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

    /// Signature over the domain-separated signing message.
    #[must_use]
    pub const fn signature(&self) -> ConsensusSignature {
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
        ShardId,
        BlockHeight,
        Round,
        ValidatorId,
        ConsensusSignature,
        ProposerTimestamp,
    ) {
        (
            self.block_hash,
            self.shard_id,
            self.height,
            self.round,
            self.voter,
            self.signature,
            self.timestamp,
        )
    }

    /// Build the canonical signing message for this vote.
    ///
    /// The [`BlockVoteMessage`] domain separates it from every other signature.
    /// This is the same message used for QC aggregated signature verification.
    ///
    /// `parent_block_hash` isn't stored on the vote; the verifier supplies it
    /// (from the block header, or the QC's own field for an aggregate).
    #[must_use]
    pub(crate) fn signing_message(
        &self,
        network: &NetworkDefinition,
        parent_block_hash: &BlockHash,
    ) -> Vec<u8> {
        signed_bytes(
            &BlockVoteMessage {
                shard_group: self.shard_id,
                height: self.height,
                round: self.round,
                block_hash: self.block_hash,
                parent_block_hash: *parent_block_hash,
            },
            network,
        )
    }
}

/// Inputs the [`BlockVote`] verifier reads against. Borrows everything;
/// nothing is consumed.
#[derive(Debug, Clone, Copy)]
pub struct BlockVoteContext<'a> {
    /// Network identifier — feeds the domain-separated signing message.
    pub(crate) network: &'a NetworkDefinition,
    /// Public key of the voter who cast this vote.
    pub(crate) voter_public_key: &'a ConsensusPublicKey,
    /// Parent of the voted block (from its header), bound into the signing message.
    pub(crate) parent_block_hash: BlockHash,
    /// Scheme verifier the signature check runs through.
    pub(crate) verifier: &'a dyn Verifier,
}

/// Failure modes of [`BlockVote`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BlockVoteVerifyError {
    /// The signature did not validate against the voter's public key
    /// for the vote's domain-separated signing message.
    #[error("signature invalid")]
    InvalidSignature,
}

/// Construction asserts: the signature on the vote validates against
/// the voter's public key for the domain-separated signing message
/// `BlockVoteMessage`.
///
/// Construction goes through one of three gates:
///
/// - [`<BlockVote as Verify>::verify`](Verify::verify) — runs the
///   signature check against the voter's public key.
/// - [`Verified::<BlockVote>::verify_batch`] — runs the same predicate
///   over a slice using the same-message batch optimisation, with
///   individual-verify fallback when the batch fails.
/// - [`Verified::<BlockVote>::sign_local`] — signs a fresh vote with
///   the caller's key; the act of signing is the predicate witness.
impl Verify<&BlockVoteContext<'_>> for BlockVote {
    type Error = BlockVoteVerifyError;

    fn verify(&self, ctx: &BlockVoteContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let message = self.signing_message(ctx.network, &ctx.parent_block_hash);
        if !ctx
            .verifier
            .verify(ctx.voter_public_key, &message, &self.signature)
        {
            return Err(BlockVoteVerifyError::InvalidSignature);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<BlockVote> {
    /// Sign a fresh [`BlockVote`] with `signer` and return its verified
    /// form.
    ///
    /// The predicate holds by construction: the signature over the
    /// canonical `BlockVoteMessage` is produced by `signer` inside
    /// this call, so any later
    /// [`<BlockVote as Verify>::verify`](Verify::verify) call against
    /// the matching public key would succeed. Used at proposer/voter
    /// sites that need the verified value immediately for local-fast-
    /// path consumers (e.g. echoing the signed vote back to the local
    /// [`VoteSet`](crate::Verified)).
    ///
    /// # Errors
    ///
    /// Propagates [`SignError`] when the signer cannot sign.
    #[allow(clippy::too_many_arguments)] // mirrors the 7 stored fields plus the network identity
    pub fn sign_local(
        network: &NetworkDefinition,
        block_hash: BlockHash,
        parent_block_hash: BlockHash,
        shard_id: ShardId,
        height: BlockHeight,
        round: Round,
        voter: ValidatorId,
        signer: &dyn Signer,
        timestamp: ProposerTimestamp,
    ) -> Result<Self, SignError> {
        // SAFETY: the signature is produced by `signer` over the
        // canonical `BlockVoteMessage`, which is exactly the
        // `BlockVote::verify` predicate's check against this voter's
        // matching pubkey.
        Ok(Self::new_unchecked(BlockVote::new(
            network,
            block_hash,
            parent_block_hash,
            shard_id,
            height,
            round,
            voter,
            signer,
            timestamp,
        )?))
    }

    /// Verify a slice of `(vote, pubkey)` pairs against a single
    /// `signing_message` using the same-message batch optimisation.
    ///
    /// Every vote in the batch must have been signed over `signing_message`
    /// (the canonical [`BlockVoteMessage`] for some `block_hash`,
    /// `height`, `round`, `shard_id`). The caller is responsible
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
        verifier: &dyn Verifier,
        signing_message: &[u8],
        votes: Vec<(BlockVote, ConsensusPublicKey)>,
    ) -> Vec<Option<Self>> {
        if votes.is_empty() {
            return Vec::new();
        }

        let messages: Vec<&[u8]> = vec![signing_message; votes.len()];
        let signatures: Vec<ConsensusSignature> =
            votes.iter().map(|(v, _)| v.signature()).collect();
        let public_keys: Vec<ConsensusPublicKey> = votes.iter().map(|(_, pk)| *pk).collect();

        // SAFETY (both arms): the scheme batch verify confirms each
        // signature against its paired public key over `signing_message`,
        // which is exactly the `BlockVote::verify` predicate (the
        // caller's contract is to pass votes that share that signing
        // message).
        let verdicts = verifier.batch_verify(&messages, &signatures, &public_keys);
        votes
            .into_iter()
            .zip(verdicts)
            .map(|((vote, _), ok)| ok.then(|| Self::new_unchecked(vote)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};

    use super::*;
    use crate::Hash;

    /// All-valid batch verifies via the fast path and yields one
    /// `Some(verified)` per input position.
    #[test]
    fn verify_batch_all_valid_returns_all_verified() {
        let net = NetworkDefinition::simulator();
        let message = signed_bytes(
            &BlockVoteMessage {
                shard_group: ShardId::ROOT,
                height: BlockHeight::new(1),
                round: Round::INITIAL,
                block_hash: BlockHash::from_raw(Hash::from_bytes(&[1u8; 32])),
                parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            },
            &net,
        );
        let votes: Vec<_> = (0..3)
            .map(|i| {
                let signer = BlsSigner::generate();
                let signature = signer.sign(&message).expect("sign");
                let pk = signer.public_key();
                let vote = BlockVote::from_parts(
                    BlockHash::from_raw(Hash::from_bytes(&[1u8; 32])),
                    ShardId::ROOT,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    ValidatorId::new(i),
                    signature,
                    ProposerTimestamp::ZERO,
                );
                (vote, pk)
            })
            .collect();

        let results = Verified::<BlockVote>::verify_batch(&BlsVerifier, &message, votes);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(Option::is_some));
    }

    /// One forged signature in the batch triggers the per-vote fallback;
    /// every honest vote still surfaces verified, the forged position
    /// surfaces `None`.
    #[test]
    fn verify_batch_falls_back_and_drops_only_the_forged_vote() {
        let net = NetworkDefinition::simulator();
        let message = signed_bytes(
            &BlockVoteMessage {
                shard_group: ShardId::ROOT,
                height: BlockHeight::new(1),
                round: Round::INITIAL,
                block_hash: BlockHash::from_raw(Hash::from_bytes(&[2u8; 32])),
                parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            },
            &net,
        );
        let mut votes: Vec<(BlockVote, ConsensusPublicKey)> = Vec::new();
        for i in 0..3u64 {
            let signer = BlsSigner::generate();
            let signature = signer.sign(&message).expect("sign");
            let vote = BlockVote::from_parts(
                BlockHash::from_raw(Hash::from_bytes(&[2u8; 32])),
                ShardId::ROOT,
                BlockHeight::new(1),
                Round::INITIAL,
                ValidatorId::new(i),
                signature,
                ProposerTimestamp::ZERO,
            );
            votes.push((vote, signer.public_key()));
        }

        // Replace the middle vote's pubkey with a fresh unrelated one so the
        // signature no longer validates.
        let intruder = BlsSigner::generate();
        votes[1].1 = intruder.public_key();

        let results = Verified::<BlockVote>::verify_batch(&BlsVerifier, &message, votes);
        assert_eq!(results.len(), 3);
        assert!(results[0].is_some());
        assert!(results[1].is_none());
        assert!(results[2].is_some());
    }

    /// Empty input produces an empty output (no allocation, no fallback).
    #[test]
    fn verify_batch_empty_input_returns_empty() {
        let results = Verified::<BlockVote>::verify_batch(&BlsVerifier, b"unused", Vec::new());
        assert!(results.is_empty());
    }
}
