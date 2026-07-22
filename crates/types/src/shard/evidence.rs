//! Shard consensus equivocation and fork evidence.
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
//!
//! [`ShardForkProof`] is self-authenticating proof that a shard's
//! committee committed two conflicting chains at one height — impossible
//! below f+1 corrupt seats (INV-SHARD-1). It is built over
//! [`CommitProof`]s: a QC certifies availability, not canonicality (an
//! f+1..2f committee can certify two blocks at one height without a
//! safe-vote violation), so the proof carries the committing *structure*
//! — a round-contiguous two-chain — that a bare QC cannot forge. The fork
//! proof is round-invariant: it stands whatever round layout the attacker
//! chose, whereas naming the individual double-signers
//! ([`ShardForkProof::same_round_conflict`]) needs a same-round
//! sub-structure and is only a bonus.

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeader, BlockHeight, Bls12381G1PublicKey, Bls12381G2Signature,
    CertifiedBlockHeader, NetworkDefinition, QcContext, QcVerifyError, QuorumCertificate, Round,
    ShardId, TopologySchedule, ValidatorId, Verify, VoteCount, block_vote_message,
    verify_bls12381_v1,
};

/// Cap on a [`CommitProof`]'s ancestry-link length.
///
/// A block commits as the prefix of a later two-chain only across a
/// bounded view-change gap (INV-SHARD-4), so the parent-hash link from the
/// directly-committed block down to the proven block is short. Caps
/// verifier work and, once the proof rides gossip, wire decode.
pub const MAX_COMMIT_PROOF_ANCESTRY: usize = 256;

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

/// A committee resolved for one QC in a [`CommitProof`].
///
/// Signer public keys in committee (bitfield) order, plus the quorum
/// threshold. Produced by [`ShardForkProof::resolve_committees`] from the
/// topology schedule so an off-thread verifier
/// ([`ShardForkProof::verify_resolved`]) runs the BLS work without the
/// schedule in hand — the same emitter-resolves pattern the beacon-block
/// verify action uses.
#[derive(Debug, Clone)]
pub struct ResolvedCommittee {
    /// Committee public keys, positionally aligned to the QC's signer
    /// bitfield.
    pub public_keys: Vec<Bls12381G1PublicKey>,
    /// Quorum threshold for the shard at the QC's window.
    pub quorum_threshold: VoteCount,
}

/// Proof that a specific block committed on its source shard — the
/// artifact a bare QC cannot forge.
///
/// The commit is witnessed by a round-contiguous two-chain: `child`
/// certifies `certified` (`child.parent == certified.hash`,
/// `child.height == certified.height + 1`, `child.round ==
/// certified.round + 1`), which is exactly the HotStuff-2 direct-commit
/// rule. In the common case `certified` *is* the proven block and
/// `ancestry` is empty. When the proven block committed only as the
/// *prefix* of a later two-chain after a view change (INV-SHARD-4),
/// `ancestry` is the parent-hash header chain from `certified`'s parent
/// down to the proven block: each link is pinned by the hash chain
/// descending from the QC-committed `certified`, so no signature is
/// needed below the two-chain — collision resistance carries the rest.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct CommitProof {
    /// Lower block of the committing two-chain — directly committed by
    /// [`Self::child`]. The proven block when [`Self::ancestry`] is empty.
    certified: CertifiedBlockHeader,
    /// Round-contiguous child that commits [`Self::certified`].
    child: CertifiedBlockHeader,
    /// Parent-hash header chain from [`Self::certified`]'s parent down to
    /// the proven block; empty when `certified` is itself the proven
    /// block. `ancestry[0]` is `certified`'s parent; `ancestry[i].hash()
    /// == ancestry[i-1].parent_block_hash()`; the last element is the
    /// proven block.
    ancestry: Vec<BlockHeader>,
}

/// Failure modes of [`CommitProof`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum CommitProofVerifyError {
    /// A member's QC does not commit its own header (`qc.block_hash !=
    /// header.hash`, or a shard/height mismatch).
    #[error("commit proof header/QC linkage mismatch")]
    Linkage,
    /// The two-chain crosses shards, or an ancestry link does.
    #[error("commit proof spans shards")]
    ShardMismatch,
    /// `child` does not extend `certified` (parent hash or height off).
    #[error("commit proof child does not extend the certified block")]
    NotAChild,
    /// `child.round != certified.round + 1` — not a direct commit.
    #[error("commit proof child is not round-contiguous")]
    NotRoundContiguous,
    /// An ancestry link's hash or height does not chain down from
    /// `certified`.
    #[error("commit proof ancestry link is broken")]
    AncestryBroken,
    /// The ancestry link exceeds [`MAX_COMMIT_PROOF_ANCESTRY`].
    #[error("commit proof ancestry link is too long")]
    AncestryTooLong,
    /// A member QC failed BLS verification against its committee.
    #[error("commit proof QC verification failed: {0}")]
    Qc(#[from] QcVerifyError),
}

impl CommitProof {
    /// Build a commit proof from a two-chain and its ancestry link.
    #[must_use]
    pub const fn new(
        certified: CertifiedBlockHeader,
        child: CertifiedBlockHeader,
        ancestry: Vec<BlockHeader>,
    ) -> Self {
        Self {
            certified,
            child,
            ancestry,
        }
    }

    /// A direct-commit proof: `certified` is itself the proven block,
    /// committed by its round-contiguous `child`.
    #[must_use]
    pub const fn direct(certified: CertifiedBlockHeader, child: CertifiedBlockHeader) -> Self {
        Self::new(certified, child, Vec::new())
    }

    /// The shard this proof is on.
    #[must_use]
    pub const fn shard(&self) -> ShardId {
        self.certified.shard_id()
    }

    /// Lower block of the committing two-chain — the branch head this
    /// proof commits (the proven block itself for a direct commit).
    #[must_use]
    pub const fn certified(&self) -> &CertifiedBlockHeader {
        &self.certified
    }

    /// Hash of the proven block — `certified`'s hash for a direct commit,
    /// or the bottom of the ancestry link for a prefix commit.
    #[must_use]
    pub fn proven_block_hash(&self) -> BlockHash {
        self.ancestry
            .last()
            .map_or_else(|| self.certified.block_hash(), BlockHeader::hash)
    }

    /// Height of the proven block.
    #[must_use]
    pub fn proven_height(&self) -> BlockHeight {
        self.ancestry
            .last()
            .map_or_else(|| self.certified.height(), BlockHeader::height)
    }

    /// The two headers carrying QCs, in canonical order. Both
    /// [`ShardForkProof::resolve_committees`] and
    /// [`ShardForkProof::verify_resolved`] iterate QCs through this, so
    /// resolved committees always line up positionally with the QCs they
    /// verify.
    const fn qc_headers(&self) -> [&CertifiedBlockHeader; 2] {
        [&self.certified, &self.child]
    }

    /// Structural checks that need no committee: header/QC linkage, the
    /// round-contiguous two-chain shape, and a well-formed ancestry link.
    fn verify_structure(&self) -> Result<(), CommitProofVerifyError> {
        for ch in self.qc_headers() {
            if ch.qc().block_hash() != ch.block_hash()
                || ch.qc().shard_id() != ch.shard_id()
                || ch.qc().height() != ch.height()
            {
                return Err(CommitProofVerifyError::Linkage);
            }
        }

        if self.child.shard_id() != self.certified.shard_id() {
            return Err(CommitProofVerifyError::ShardMismatch);
        }
        if self.child.header().parent_block_hash() != self.certified.block_hash()
            || self.child.height() != self.certified.height().next()
        {
            return Err(CommitProofVerifyError::NotAChild);
        }
        if self.child.header().round() != self.certified.header().round().next() {
            return Err(CommitProofVerifyError::NotRoundContiguous);
        }

        if self.ancestry.len() > MAX_COMMIT_PROOF_ANCESTRY {
            return Err(CommitProofVerifyError::AncestryTooLong);
        }
        let mut expected_hash = self.certified.header().parent_block_hash();
        let mut expected_height = self.certified.height().prev();
        for link in &self.ancestry {
            if link.shard_id() != self.certified.shard_id() {
                return Err(CommitProofVerifyError::ShardMismatch);
            }
            if link.hash() != expected_hash || expected_height != Some(link.height()) {
                return Err(CommitProofVerifyError::AncestryBroken);
            }
            expected_hash = link.parent_block_hash();
            expected_height = link.height().prev();
        }
        Ok(())
    }

    /// BLS-verify both member QCs against their resolved committees.
    /// `committees` is `[certified_committee, child_committee]`.
    fn verify_qcs(
        &self,
        network: &NetworkDefinition,
        committees: &[ResolvedCommittee],
    ) -> Result<(), CommitProofVerifyError> {
        for (ch, committee) in self.qc_headers().into_iter().zip(committees) {
            let ctx = QcContext {
                network,
                public_keys: &committee.public_keys,
                quorum_threshold: committee.quorum_threshold,
            };
            ch.qc().verify(&ctx)?;
        }
        Ok(())
    }
}

/// Self-authenticating proof that a shard committee ran a fork: two commit
/// proofs for the same shard and height with different proven-block hashes.
///
/// Two committed chains at one height is impossible for an honest-majority
/// committee whatever the round layout (INV-SHARD-1), so the proof stands
/// on its own — no beacon boundary or other external reference is needed to
/// trust it. The cross-victim shape: victim B holds one commit proof,
/// victim C the other, and together they are the fork proof. The consequence
/// is fence + full committee re-draw.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum ShardForkProof {
    /// Two conflicting commits at one `(shard, height)`.
    ConflictingCommits {
        /// One committed branch.
        a: CommitProof,
        /// The other committed branch (different proven-block hash).
        b: CommitProof,
    },
}

/// Failure modes of [`ShardForkProof`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ShardForkProofVerifyError {
    /// The first (`a`) commit proof failed.
    #[error("commit proof a: {0}")]
    ProofA(CommitProofVerifyError),
    /// The second (`b`) commit proof failed.
    #[error("commit proof b: {0}")]
    ProofB(CommitProofVerifyError),
    /// A QC's committee could not be resolved from the schedule (the
    /// governing epoch is not folded yet); the caller defers.
    #[error("commit proof committee unresolved")]
    CommitteeUnresolved,
    /// The resolved-committee count does not match the proof's QC count.
    #[error("resolved committee count mismatch")]
    CommitteeCountMismatch,
    /// The two proofs are on different shards.
    #[error("conflicting commits span shards")]
    ShardMismatch,
    /// The two proven blocks are at different heights.
    #[error("conflicting commits are at different heights")]
    HeightMismatch,
    /// The two proven blocks share a hash — no contradiction.
    #[error("no conflict: proven blocks are equal")]
    NotConflicting,
}

impl ShardForkProof {
    /// The shard the fork is on.
    #[must_use]
    pub const fn shard(&self) -> ShardId {
        let Self::ConflictingCommits { a, .. } = self;
        a.shard()
    }

    /// The forked height.
    #[must_use]
    pub fn height(&self) -> BlockHeight {
        let Self::ConflictingCommits { a, .. } = self;
        a.proven_height()
    }

    /// Every QC-bearing header in the proof, in canonical order —
    /// `[a.certified, a.child, b.certified, b.child]`. The single ordering
    /// both committee resolution and verification iterate.
    fn qc_headers(&self) -> Vec<&CertifiedBlockHeader> {
        let Self::ConflictingCommits { a, b } = self;
        let mut v = a.qc_headers().to_vec();
        v.extend(b.qc_headers());
        v
    }

    /// Resolve each QC's committee from the schedule, keyed by the QC's
    /// window (`committee(h) = at(WT_{h-1})`, recovery-bridged like any
    /// certified artifact). `None` if any QC's governing epoch is not
    /// folded — the caller defers, exactly as cross-shard consumption
    /// does. The result lines up positionally with [`Self::qc_headers`].
    #[must_use]
    pub fn resolve_committees(
        &self,
        schedule: &TopologySchedule,
    ) -> Option<Vec<ResolvedCommittee>> {
        self.qc_headers()
            .into_iter()
            .map(|ch| {
                let shard = ch.shard_id();
                let anchor_wt = ch.header().parent_qc().weighted_timestamp();
                let qc_wt = ch.qc().weighted_timestamp();
                let (snapshot, _bridged) =
                    schedule.at_for_shard_certified(shard, anchor_wt, qc_wt)?;
                let public_keys = snapshot
                    .consensus_committee_for_shard(shard)
                    .iter()
                    .map(|v| snapshot.public_key(*v))
                    .collect::<Option<Vec<_>>>()?;
                Some(ResolvedCommittee {
                    public_keys,
                    quorum_threshold: snapshot.quorum_threshold_for_shard(shard),
                })
            })
            .collect()
    }

    /// Verify against committees resolved from `schedule`. The canonical
    /// entry, used where the schedule is in hand (the beacon fold, inline
    /// checks). Off-thread verifiers resolve once via
    /// [`Self::resolve_committees`] and call [`Self::verify_resolved`].
    ///
    /// # Errors
    ///
    /// [`ShardForkProofVerifyError::CommitteeUnresolved`] if any QC's epoch
    /// is not folded; otherwise the first failing structural, crypto, or
    /// contradiction check.
    pub fn verify(&self, schedule: &TopologySchedule) -> Result<(), ShardForkProofVerifyError> {
        let committees = self
            .resolve_committees(schedule)
            .ok_or(ShardForkProofVerifyError::CommitteeUnresolved)?;
        self.verify_resolved(schedule.head().network(), &committees)
    }

    /// Verify against pre-resolved committees (positionally aligned to
    /// [`Self::qc_headers`]). Runs structure, BLS, and the contradiction
    /// check.
    ///
    /// # Errors
    ///
    /// A [`ShardForkProofVerifyError`] naming the failing check.
    pub fn verify_resolved(
        &self,
        network: &NetworkDefinition,
        committees: &[ResolvedCommittee],
    ) -> Result<(), ShardForkProofVerifyError> {
        if committees.len() != self.qc_headers().len() {
            return Err(ShardForkProofVerifyError::CommitteeCountMismatch);
        }
        let Self::ConflictingCommits { a, b } = self;
        a.verify_structure()
            .map_err(ShardForkProofVerifyError::ProofA)?;
        b.verify_structure()
            .map_err(ShardForkProofVerifyError::ProofB)?;
        a.verify_qcs(network, &committees[0..2])
            .map_err(ShardForkProofVerifyError::ProofA)?;
        b.verify_qcs(network, &committees[2..4])
            .map_err(ShardForkProofVerifyError::ProofB)?;
        if a.shard() != b.shard() {
            return Err(ShardForkProofVerifyError::ShardMismatch);
        }
        if a.proven_height() != b.proven_height() {
            return Err(ShardForkProofVerifyError::HeightMismatch);
        }
        if a.proven_block_hash() == b.proven_block_hash() {
            return Err(ShardForkProofVerifyError::NotConflicting);
        }
        Ok(())
    }

    /// Extract any same-`(height, round)` different-hash QC pair across the
    /// proof's QCs — a within-committee double-sign whose signer bitfields
    /// intersect to the equivocators (attributable only once proof of
    /// possession makes bitfield membership sound). Fence and re-draw need
    /// none of this;
    /// jailing does, and lands only against an attacker who left a
    /// same-round sub-pair. `None` when every QC sits at a distinct round —
    /// the round-invariant fork proof still stands.
    #[must_use]
    pub fn same_round_conflict(&self) -> Option<(&QuorumCertificate, &QuorumCertificate)> {
        let qcs: Vec<&QuorumCertificate> = self.qc_headers().iter().map(|ch| ch.qc()).collect();
        for i in 0..qcs.len() {
            for j in (i + 1)..qcs.len() {
                if qcs[i].height() == qcs[j].height()
                    && qcs[i].round() == qcs[j].round()
                    && qcs[i].block_hash() != qcs[j].block_hash()
                {
                    return Some((qcs[i], qcs[j]));
                }
            }
        }
        None
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

    // ─── Fork-proof fixtures and tests ──────────────────────────────────

    mod fork {
        use std::collections::BTreeMap;
        use std::sync::Arc;

        use super::super::*;
        use crate::test_utils::TestCommittee;
        use crate::{
            BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHeader, CertificateRoot, ChainOrigin,
            Epoch, Hash, InFlightCount, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot,
            SignerBitfield, StateRoot, TopologySchedule, TransactionRoot, WeightedTimestamp,
        };

        const SHARD: ShardId = ShardId::ROOT;

        fn network() -> NetworkDefinition {
            NetworkDefinition::simulator()
        }

        /// One committee for every window, so any QC's WT resolves to it.
        fn schedule(committee: &TestCommittee) -> TopologySchedule {
            TopologySchedule::single(Arc::new(committee.topology_snapshot(1)))
        }

        /// A `BlockHeader` distinguished by `salt` (varies the hash so
        /// siblings at one `(height, round)` differ). Genesis parent QC
        /// carries the anchor WT.
        fn header(
            height: BlockHeight,
            round: Round,
            parent_block_hash: BlockHash,
            salt: u64,
        ) -> BlockHeader {
            BlockHeader::new(
                SHARD,
                height,
                parent_block_hash,
                QuorumCertificate::genesis(SHARD, ChainOrigin::ROOT),
                ValidatorId::new(0),
                ProposerTimestamp::from_millis(salt),
                round,
                false,
                StateRoot::ZERO,
                TransactionRoot::ZERO,
                CertificateRoot::ZERO,
                LocalReceiptRoot::ZERO,
                ProvisionsRoot::ZERO,
                Vec::new(),
                BTreeMap::new(),
                InFlightCount::ZERO,
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        }

        /// Pair a header with a genuine quorum QC signed by `committee`.
        fn certify(committee: &TestCommittee, header: BlockHeader) -> CertifiedBlockHeader {
            let net = network();
            let block_hash = header.hash();
            let msg = block_vote_message(
                &net,
                header.shard_id(),
                header.height(),
                header.round(),
                &block_hash,
                &header.parent_block_hash(),
            );
            let quorum = committee.quorum_indices();
            let sigs: Vec<Bls12381G2Signature> = quorum
                .iter()
                .map(|&i| committee.keypair(i).sign_v1(&msg))
                .collect();
            let agg = Bls12381G2Signature::aggregate(&sigs, true).expect("aggregate");
            let mut signers = SignerBitfield::new(committee.size());
            for &i in &quorum {
                signers.set(i);
            }
            let qc = QuorumCertificate::new(
                block_hash,
                header.shard_id(),
                header.height(),
                header.parent_block_hash(),
                header.round(),
                signers,
                agg,
                WeightedTimestamp::from_millis(header.height().inner() * 1_000),
            );
            CertifiedBlockHeader::new(header, qc)
        }

        /// A direct-commit proof for a block at `(height, round)` with a
        /// round-contiguous child. `salt` distinguishes sibling branches.
        fn direct_proof(
            committee: &TestCommittee,
            height: BlockHeight,
            round: Round,
            parent: BlockHash,
            salt: u64,
        ) -> CommitProof {
            let block = certify(committee, header(height, round, parent, salt));
            let child = certify(
                committee,
                header(height.next(), round.next(), block.block_hash(), salt + 500),
            );
            CommitProof::direct(block, child)
        }

        /// Two committed branches at one height with distinct hashes.
        fn conflicting_commits(committee: &TestCommittee) -> ShardForkProof {
            let parent = BlockHash::from_raw(Hash::from_bytes(b"fork-parent"));
            ShardForkProof::ConflictingCommits {
                a: direct_proof(committee, BlockHeight::new(9), Round::new(9), parent, 1),
                b: direct_proof(committee, BlockHeight::new(9), Round::new(11), parent, 2),
            }
        }

        #[test]
        fn direct_fork_assembles_and_verifies() {
            let committee = TestCommittee::new(4, 1);
            let proof = conflicting_commits(&committee);
            assert_eq!(proof.verify(&schedule(&committee)), Ok(()));
            assert_eq!(proof.shard(), SHARD);
            assert_eq!(proof.height(), BlockHeight::new(9));
        }

        #[test]
        fn equal_proven_blocks_are_not_a_conflict() {
            let committee = TestCommittee::new(4, 2);
            let parent = BlockHash::from_raw(Hash::from_bytes(b"same"));
            // Byte-identical branches — the same committed block twice.
            let proof = ShardForkProof::ConflictingCommits {
                a: direct_proof(&committee, BlockHeight::new(4), Round::new(4), parent, 7),
                b: direct_proof(&committee, BlockHeight::new(4), Round::new(4), parent, 7),
            };
            assert_eq!(
                proof.verify(&schedule(&committee)),
                Err(ShardForkProofVerifyError::NotConflicting)
            );
        }

        #[test]
        fn wrong_committee_fails_bls() {
            let committee = TestCommittee::new(4, 3);
            let proof = conflicting_commits(&committee);
            // Verify against a different committee's keys.
            let other = TestCommittee::new(4, 999);
            let err = proof.verify(&schedule(&other)).unwrap_err();
            assert!(
                matches!(
                    err,
                    ShardForkProofVerifyError::ProofA(CommitProofVerifyError::Qc(_))
                ),
                "expected a QC failure, got {err:?}"
            );
        }

        #[test]
        fn non_round_contiguous_child_rejected() {
            let committee = TestCommittee::new(4, 4);
            let parent = BlockHash::from_raw(Hash::from_bytes(b"p"));
            let block = certify(
                &committee,
                header(BlockHeight::new(5), Round::new(5), parent, 1),
            );
            // Child at round+2, not round+1 — a valid QC but no direct commit.
            let child = certify(
                &committee,
                header(BlockHeight::new(6), Round::new(7), block.block_hash(), 2),
            );
            let good = direct_proof(&committee, BlockHeight::new(5), Round::new(5), parent, 3);
            let proof = ShardForkProof::ConflictingCommits {
                a: CommitProof::direct(block, child),
                b: good,
            };
            assert_eq!(
                proof.verify(&schedule(&committee)),
                Err(ShardForkProofVerifyError::ProofA(
                    CommitProofVerifyError::NotRoundContiguous
                ))
            );
        }

        #[test]
        fn child_not_extending_parent_rejected() {
            let committee = TestCommittee::new(4, 5);
            let parent = BlockHash::from_raw(Hash::from_bytes(b"p"));
            let block = certify(
                &committee,
                header(BlockHeight::new(5), Round::new(5), parent, 1),
            );
            // Child whose parent hash points elsewhere.
            let child = certify(
                &committee,
                header(
                    BlockHeight::new(6),
                    Round::new(6),
                    BlockHash::from_raw(Hash::from_bytes(b"elsewhere")),
                    2,
                ),
            );
            let proof = ShardForkProof::ConflictingCommits {
                a: CommitProof::direct(block, child),
                b: direct_proof(&committee, BlockHeight::new(5), Round::new(5), parent, 3),
            };
            assert_eq!(
                proof.verify(&schedule(&committee)),
                Err(ShardForkProofVerifyError::ProofA(
                    CommitProofVerifyError::NotAChild
                ))
            );
        }

        #[test]
        fn prefix_commit_branch_verifies_via_ancestry() {
            // One branch prefix-commits block B@8 as the prefix of the
            // two-chain D@9 ← child@10 (round-contiguous, post view change),
            // reaching B through the ancestry link; the other directly
            // commits a different block B'@8. Both proven at height 8 with
            // distinct hashes — a fork whose winning branch is a prefix
            // commit.
            let committee = TestCommittee::new(4, 6);
            let parent = BlockHash::from_raw(Hash::from_bytes(b"grandparent"));
            let b = header(BlockHeight::new(8), Round::new(8), parent, 1);
            let d = certify(
                &committee,
                header(BlockHeight::new(9), Round::new(20), b.hash(), 2),
            );
            let child = certify(
                &committee,
                header(BlockHeight::new(10), Round::new(21), d.block_hash(), 3),
            );
            let a = CommitProof::new(d, child, vec![b.clone()]);
            assert_eq!(a.proven_height(), BlockHeight::new(8));
            assert_eq!(a.proven_block_hash(), b.hash());

            let other = direct_proof(&committee, BlockHeight::new(8), Round::new(8), parent, 99);
            let fork = ShardForkProof::ConflictingCommits { a, b: other };
            assert_eq!(fork.verify(&schedule(&committee)), Ok(()));
        }

        #[test]
        fn same_round_conflict_extracts_pair_when_present() {
            let committee = TestCommittee::new(4, 8);
            let parent = BlockHash::from_raw(Hash::from_bytes(b"p"));
            // Both branches' certified blocks sign at round 9 — a same-round
            // double-sign the committee produced.
            let same_round = ShardForkProof::ConflictingCommits {
                a: direct_proof(&committee, BlockHeight::new(9), Round::new(9), parent, 1),
                b: direct_proof(&committee, BlockHeight::new(9), Round::new(9), parent, 2),
            };
            assert!(same_round.same_round_conflict().is_some());

            // Round-spaced branches leave no seat signing twice at one round.
            let round_spaced = conflicting_commits(&committee);
            assert!(round_spaced.same_round_conflict().is_none());
        }

        #[test]
        fn unresolvable_committee_defers() {
            let committee = TestCommittee::new(4, 9);
            let proof = conflicting_commits(&committee);
            // A schedule whose only epoch is far above the QCs' windows: the
            // future-epoch lookup is NotYetCommitted, so resolution fails and
            // the caller defers rather than treating it as invalid.
            let snapshot = Arc::new(committee.topology_snapshot(1));
            let mut schedule = TopologySchedule::new(1_000, Epoch::new(50), Arc::clone(&snapshot));
            schedule.insert(Epoch::new(50), snapshot);
            assert_eq!(
                proof.verify(&schedule),
                Err(ShardForkProofVerifyError::CommitteeUnresolved)
            );
        }

        #[test]
        fn fork_proof_sbor_round_trip() {
            use sbor::{basic_decode, basic_encode};
            let committee = TestCommittee::new(4, 10);
            let proof = conflicting_commits(&committee);
            let bytes = basic_encode(&proof).unwrap();
            let decoded: ShardForkProof = basic_decode(&bytes).unwrap();
            assert_eq!(proof, decoded);
        }
    }
}
