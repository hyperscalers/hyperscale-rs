//! Shard consensus equivocation evidence.
//!
//! [`ShardVoteEquivocation`] is self-authenticating proof that one
//! validator signed two [`BlockVote`](super::vote::BlockVote)s for
//! different blocks at the same `(shard, height, round)` — a violation
//! of the one-vote-per-round rule (INV-SHARD-2) no honest key with the
//! safe-vote lock can produce. It carries the cryptographic minimum that
//! reconstructs both signing messages and runs BLS verify under the
//! signer's pubkey, so it can ride into the beacon's jail mechanism the
//! same way a beacon PC double-sign
//! ([`PcVoteEquivocation`](crate::PcVoteEquivocation)) does.

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeight, Bls12381G1PublicKey, Bls12381G2Signature, NetworkDefinition, Round,
    ShardId, ValidatorId, block_vote_message, verify_bls12381_v1,
};

/// Self-authenticating evidence that a single validator double-voted at
/// one `(shard, height, round)` for two different blocks.
///
/// Each side carries the block it voted, the parent hash the vote bound
/// in (needed to reconstruct the signing message —
/// [`block_vote_message`] binds the parent), and the BLS signature. The
/// contradiction is `block_hash_a != block_hash_b`: an honest validator
/// votes at most once per round, so two valid signatures over different
/// block hashes at the same slot prove the key voted twice.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ShardVoteEquivocation {
    /// Validator that double-voted.
    pub validator: ValidatorId,
    /// Shard the votes belong to.
    pub shard: ShardId,
    /// Height both votes were cast at.
    pub height: BlockHeight,
    /// Round both votes were cast at.
    pub round: Round,
    /// First side's voted block.
    pub block_hash_a: BlockHash,
    /// First side's parent hash, bound into the signing message.
    pub parent_block_hash_a: BlockHash,
    /// First side's BLS signature over `block_vote_message` for side A.
    pub sig_a: Bls12381G2Signature,
    /// Second side's voted block (must differ from `block_hash_a`).
    pub block_hash_b: BlockHash,
    /// Second side's parent hash, bound into the signing message.
    pub parent_block_hash_b: BlockHash,
    /// Second side's BLS signature over `block_vote_message` for side B.
    pub sig_b: Bls12381G2Signature,
}

/// Failure modes of shard vote-equivocation evidence.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ShardVoteEquivocationVerifyError {
    /// `block_hash_a == block_hash_b` — no contradiction (the same block
    /// voted twice is a duplicate, not equivocation).
    #[error("block_hash_a equals block_hash_b — no contradiction")]
    BlocksEqual,
    /// One or both signatures did not verify under the validator's pubkey.
    #[error("equivocation signature did not verify")]
    BadSignature,
}

/// Verify shard vote-equivocation evidence against the signer's pubkey.
///
/// The two block hashes must differ, and both signatures must verify
/// over their respective [`block_vote_message`] under `pubkey`. The
/// caller resolves `pubkey` for `ev.validator` from the validator
/// registry (the beacon fold) or the topology snapshot (a gossip
/// receiver); no committee resolution is needed because no honest key
/// signs two blocks at one `(shard, height, round)` regardless of which
/// committee it sits in.
///
/// # Errors
///
/// Returns a [`ShardVoteEquivocationVerifyError`] variant naming the
/// failing predicate.
pub fn verify_shard_vote_equivocation(
    ev: &ShardVoteEquivocation,
    network: &NetworkDefinition,
    pubkey: &Bls12381G1PublicKey,
) -> Result<(), ShardVoteEquivocationVerifyError> {
    if ev.block_hash_a == ev.block_hash_b {
        return Err(ShardVoteEquivocationVerifyError::BlocksEqual);
    }
    let msg_a = block_vote_message(
        network,
        ev.shard,
        ev.height,
        ev.round,
        &ev.block_hash_a,
        &ev.parent_block_hash_a,
    );
    let msg_b = block_vote_message(
        network,
        ev.shard,
        ev.height,
        ev.round,
        &ev.block_hash_b,
        &ev.parent_block_hash_b,
    );
    if verify_bls12381_v1(&msg_a, pubkey, &ev.sig_a)
        && verify_bls12381_v1(&msg_b, pubkey, &ev.sig_b)
    {
        Ok(())
    } else {
        Err(ShardVoteEquivocationVerifyError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use radix_common::crypto::Bls12381G1PrivateKey;

    use super::*;
    use crate::{BlockVote, Hash, ProposerTimestamp, generate_bls_keypair};

    /// Sign a real block vote and return `(block_hash, parent_hash, sig)`
    /// so tests assemble evidence from genuine signatures.
    fn signed_side(
        network: &NetworkDefinition,
        sk: &Bls12381G1PrivateKey,
        shard: ShardId,
        height: BlockHeight,
        round: Round,
        block_hash: BlockHash,
        parent_block_hash: BlockHash,
    ) -> (BlockHash, BlockHash, Bls12381G2Signature) {
        let vote = BlockVote::new(
            network,
            block_hash,
            parent_block_hash,
            shard,
            height,
            round,
            ValidatorId::new(7),
            sk,
            ProposerTimestamp::ZERO,
        );
        (block_hash, parent_block_hash, vote.signature())
    }

    fn hash(bytes: &[u8]) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(bytes))
    }

    /// Two genuine signatures over different blocks at one slot verify.
    #[test]
    fn genuine_double_vote_verifies() {
        let net = NetworkDefinition::simulator();
        let sk = generate_bls_keypair();
        let pk = sk.public_key();
        let (shard, height, round) = (ShardId::ROOT, BlockHeight::new(4), Round::INITIAL);
        let (ba, pa, sa) = signed_side(
            &net,
            &sk,
            shard,
            height,
            round,
            hash(b"block-a"),
            hash(b"parent-a"),
        );
        let (bb, pb, sb) = signed_side(
            &net,
            &sk,
            shard,
            height,
            round,
            hash(b"block-b"),
            hash(b"parent-b"),
        );
        let ev = ShardVoteEquivocation {
            validator: ValidatorId::new(7),
            shard,
            height,
            round,
            block_hash_a: ba,
            parent_block_hash_a: pa,
            sig_a: sa,
            block_hash_b: bb,
            parent_block_hash_b: pb,
            sig_b: sb,
        };
        assert_eq!(verify_shard_vote_equivocation(&ev, &net, &pk), Ok(()));
    }

    /// Same block on both sides is a duplicate, not a contradiction —
    /// rejected before any pairing.
    #[test]
    fn equal_blocks_rejected() {
        let net = NetworkDefinition::simulator();
        let sk = generate_bls_keypair();
        let pk = sk.public_key();
        let (shard, height, round) = (ShardId::ROOT, BlockHeight::new(4), Round::INITIAL);
        let (ba, pa, sa) = signed_side(
            &net,
            &sk,
            shard,
            height,
            round,
            hash(b"block-a"),
            hash(b"parent-a"),
        );
        let ev = ShardVoteEquivocation {
            validator: ValidatorId::new(7),
            shard,
            height,
            round,
            block_hash_a: ba,
            parent_block_hash_a: pa,
            sig_a: sa,
            block_hash_b: ba,
            parent_block_hash_b: pa,
            sig_b: sa,
        };
        assert_eq!(
            verify_shard_vote_equivocation(&ev, &net, &pk),
            Err(ShardVoteEquivocationVerifyError::BlocksEqual)
        );
    }

    /// A signature that doesn't validate under the signer's key (here,
    /// a different key signed side B) is rejected.
    #[test]
    fn bad_signature_rejected() {
        let net = NetworkDefinition::simulator();
        let sk = generate_bls_keypair();
        let pk = sk.public_key();
        let intruder = generate_bls_keypair();
        let (shard, height, round) = (ShardId::ROOT, BlockHeight::new(4), Round::INITIAL);
        let (ba, pa, sa) = signed_side(
            &net,
            &sk,
            shard,
            height,
            round,
            hash(b"block-a"),
            hash(b"parent-a"),
        );
        // Side B signed by an unrelated key: the message is well-formed
        // but the signature won't verify under `pk`.
        let (bb, pb, sb) = signed_side(
            &net,
            &intruder,
            shard,
            height,
            round,
            hash(b"block-b"),
            hash(b"parent-b"),
        );
        let ev = ShardVoteEquivocation {
            validator: ValidatorId::new(7),
            shard,
            height,
            round,
            block_hash_a: ba,
            parent_block_hash_a: pa,
            sig_a: sa,
            block_hash_b: bb,
            parent_block_hash_b: pb,
            sig_b: sb,
        };
        assert_eq!(
            verify_shard_vote_equivocation(&ev, &net, &pk),
            Err(ShardVoteEquivocationVerifyError::BadSignature)
        );
    }

    /// Evidence round-trips through SBOR unchanged.
    #[test]
    fn sbor_round_trip() {
        use sbor::{basic_decode, basic_encode};
        let ev = ShardVoteEquivocation {
            validator: ValidatorId::new(7),
            shard: ShardId::ROOT,
            height: BlockHeight::new(4),
            round: Round::INITIAL,
            block_hash_a: hash(b"block-a"),
            parent_block_hash_a: hash(b"parent-a"),
            sig_a: Bls12381G2Signature([1u8; 96]),
            block_hash_b: hash(b"block-b"),
            parent_block_hash_b: hash(b"parent-b"),
            sig_b: Bls12381G2Signature([2u8; 96]),
        };
        let bytes = basic_encode(&ev).unwrap();
        let decoded: ShardVoteEquivocation = basic_decode(&bytes).unwrap();
        assert_eq!(ev, decoded);
    }
}
