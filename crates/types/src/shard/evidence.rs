//! Shard consensus equivocation and fork evidence.
//!
//! [`ShardVoteEquivocation`] is self-authenticating proof that one
//! validator signed two [`BlockVote`](super::vote::BlockVote)s for
//! different blocks at the same `(shard, height, round)` — a violation
//! of the one-vote-per-round rule (INV-SHARD-2) no honest key with the
//! safe-vote lock can produce. It carries the cryptographic minimum that
//! reconstructs both signing messages and runs signature verify under the
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

use hyperscale_crypto::Verifier;
use hyperscale_hbor::Hbor;
use thiserror::Error;

use crate::shard::commit_proof::{CommitProof, CommitProofVerifyError, ResolvedCommittee};
use crate::{
    BlockHash, BlockHeight, BlockVoteMessage, CertifiedBlockHeader, ConsensusPublicKey,
    ConsensusSignature, NetworkDefinition, QuorumCertificate, Round, ShardId, TopologySchedule,
    ValidatorId, Verified, Verify, signed_bytes,
};

/// Self-authenticating evidence that a single validator double-voted at
/// one `(shard, height, round)` for two different blocks.
///
/// Each side carries the block it voted, the parent hash the vote bound
/// in (needed to reconstruct the signing message —
/// [`BlockVoteMessage`] binds the parent), and the signature. The
/// contradiction is `block_hash_a != block_hash_b`: an honest validator
/// votes at most once per round, so two valid signatures over different
/// block hashes at the same slot prove the key voted twice.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
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
    /// First side's signature over `BlockVoteMessage` for side A.
    pub sig_a: ConsensusSignature,
    /// Second side's voted block (must differ from `block_hash_a`).
    pub block_hash_b: BlockHash,
    /// Second side's parent hash, bound into the signing message.
    pub parent_block_hash_b: BlockHash,
    /// Second side's signature over `BlockVoteMessage` for side B.
    pub sig_b: ConsensusSignature,
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
/// over their respective [`BlockVoteMessage`] under `pubkey`. The
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
    verifier: &dyn Verifier,
    ev: &ShardVoteEquivocation,
    network: &NetworkDefinition,
    pubkey: &ConsensusPublicKey,
) -> Result<(), ShardVoteEquivocationVerifyError> {
    if ev.block_hash_a == ev.block_hash_b {
        return Err(ShardVoteEquivocationVerifyError::BlocksEqual);
    }
    let msg_a = signed_bytes(
        &BlockVoteMessage {
            shard_group: ev.shard,
            height: ev.height,
            round: ev.round,
            block_hash: ev.block_hash_a,
            parent_block_hash: ev.parent_block_hash_a,
        },
        network,
    );
    let msg_b = signed_bytes(
        &BlockVoteMessage {
            shard_group: ev.shard,
            height: ev.height,
            round: ev.round,
            block_hash: ev.block_hash_b,
            parent_block_hash: ev.parent_block_hash_b,
        },
        network,
    );
    if verifier.verify(pubkey, &msg_a, &ev.sig_a) && verifier.verify(pubkey, &msg_b, &ev.sig_b) {
        Ok(())
    } else {
        Err(ShardVoteEquivocationVerifyError::BadSignature)
    }
}

/// Everything [`verify_shard_vote_equivocation`] needs beyond the
/// evidence itself: the network binding and the accused key.
#[derive(Debug, Clone, Copy)]
pub struct ShardVoteEquivocationContext<'a> {
    /// Network the votes were bound to.
    pub network: &'a NetworkDefinition,
    /// The accused validator's registered pubkey.
    pub pubkey: &'a ConsensusPublicKey,
    /// Scheme verifier the signature checks run through.
    pub verifier: &'a dyn Verifier,
}

impl Verify<&ShardVoteEquivocationContext<'_>> for ShardVoteEquivocation {
    type Error = ShardVoteEquivocationVerifyError;

    fn verify(
        &self,
        ctx: &ShardVoteEquivocationContext<'_>,
    ) -> Result<Verified<Self>, Self::Error> {
        verify_shard_vote_equivocation(ctx.verifier, self, ctx.network, ctx.pubkey)?;
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verify<&ShardVoteEquivocationContext<'_>> for Box<ShardVoteEquivocation> {
    type Error = ShardVoteEquivocationVerifyError;

    fn verify(
        &self,
        ctx: &ShardVoteEquivocationContext<'_>,
    ) -> Result<Verified<Self>, Self::Error> {
        verify_shard_vote_equivocation(ctx.verifier, self, ctx.network, ctx.pubkey)?;
        Ok(Verified::new_unchecked(self.clone()))
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
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
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

    /// Resolve each QC's committee from the schedule, keyed by the block's
    /// committee anchor — its *parent's* weighted timestamp, since that is
    /// what selects the committee that signed it — and recovery-bridged like
    /// any certified artifact. `None` if any QC's governing epoch is not
    /// folded, or if a proof carries no parent for its certified block; the
    /// caller defers, exactly as cross-shard consumption does. The result
    /// lines up positionally with [`Self::qc_headers`].
    #[must_use]
    pub fn resolve_committees(
        &self,
        schedule: &TopologySchedule,
    ) -> Option<Vec<ResolvedCommittee>> {
        let Self::ConflictingCommits { a, b } = self;
        let anchors = [
            a.certified_committee_anchor()?,
            a.child_committee_anchor(),
            b.certified_committee_anchor()?,
            b.child_committee_anchor(),
        ];
        self.qc_headers()
            .into_iter()
            .zip(anchors)
            .map(|(ch, anchor_wt)| {
                let shard = ch.shard_id();
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
    pub fn verify(
        &self,
        verifier: &dyn Verifier,
        schedule: &TopologySchedule,
    ) -> Result<(), ShardForkProofVerifyError> {
        let committees = self
            .resolve_committees(schedule)
            .ok_or(ShardForkProofVerifyError::CommitteeUnresolved)?;
        self.verify_resolved(verifier, schedule.head().network(), &committees)
    }

    /// Verify against pre-resolved committees (positionally aligned to
    /// [`Self::qc_headers`]). Runs structure, signatures, and the contradiction
    /// check.
    ///
    /// # Errors
    ///
    /// A [`ShardForkProofVerifyError`] naming the failing check.
    pub fn verify_resolved(
        &self,
        verifier: &dyn Verifier,
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
        a.verify_qcs(verifier, network, &committees[0..2])
            .map_err(ShardForkProofVerifyError::ProofA)?;
        b.verify_qcs(verifier, network, &committees[2..4])
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
    use hyperscale_crypto::Signer;
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{BlockVote, Hash, ProposerTimestamp};

    /// Sign a real block vote and return `(block_hash, parent_hash, sig)`
    /// so tests assemble evidence from genuine signatures.
    fn signed_side(
        network: &NetworkDefinition,
        sk: &BlsSigner,
        shard: ShardId,
        height: BlockHeight,
        round: Round,
        block_hash: BlockHash,
        parent_block_hash: BlockHash,
    ) -> (BlockHash, BlockHash, ConsensusSignature) {
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
        )
        .expect("sign");
        (block_hash, parent_block_hash, vote.signature())
    }

    fn hash(bytes: &[u8]) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(bytes))
    }

    /// Two genuine signatures over different blocks at one slot verify.
    #[test]
    fn genuine_double_vote_verifies() {
        let net = NetworkDefinition::simulator();
        let sk = BlsSigner::generate();
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
        assert_eq!(
            verify_shard_vote_equivocation(&BlsVerifier, &ev, &net, &pk),
            Ok(())
        );
    }

    /// Same block on both sides is a duplicate, not a contradiction —
    /// rejected before any pairing.
    #[test]
    fn equal_blocks_rejected() {
        let net = NetworkDefinition::simulator();
        let sk = BlsSigner::generate();
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
            verify_shard_vote_equivocation(&BlsVerifier, &ev, &net, &pk),
            Err(ShardVoteEquivocationVerifyError::BlocksEqual)
        );
    }

    /// A signature that doesn't validate under the signer's key (here,
    /// a different key signed side B) is rejected.
    #[test]
    fn bad_signature_rejected() {
        let net = NetworkDefinition::simulator();
        let sk = BlsSigner::generate();
        let pk = sk.public_key();
        let intruder = BlsSigner::generate();
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
            verify_shard_vote_equivocation(&BlsVerifier, &ev, &net, &pk),
            Err(ShardVoteEquivocationVerifyError::BadSignature)
        );
    }

    /// Evidence round-trips through the wire codec unchanged.
    #[test]
    fn hbor_round_trip() {
        let ev = ShardVoteEquivocation {
            validator: ValidatorId::new(7),
            shard: ShardId::ROOT,
            height: BlockHeight::new(4),
            round: Round::INITIAL,
            block_hash_a: hash(b"block-a"),
            parent_block_hash_a: hash(b"parent-a"),
            sig_a: ConsensusSignature::new([1u8; 96]),
            block_hash_b: hash(b"block-b"),
            parent_block_hash_b: hash(b"parent-b"),
            sig_b: ConsensusSignature::new([2u8; 96]),
        };
        let bytes = hbor_to_vec(&ev).unwrap();
        let decoded: ShardVoteEquivocation = hbor_from_slice(&bytes).unwrap();
        assert_eq!(ev, decoded);
    }

    // ─── Fork-proof fixtures and tests ──────────────────────────────────

    mod fork {
        use std::sync::Arc;

        use hyperscale_crypto_bls::BlsVerifier;
        use hyperscale_hbor::{Capped, from_slice as hbor_from_slice, to_vec as hbor_to_vec};

        use super::super::*;
        use crate::test_utils::{
            TestCommittee, anchor_qc, certify_header, direct_commit_proof, fork_header,
            live_fork_header,
        };
        use crate::{BlockHeader, Epoch, Hash, TopologySchedule, WeightedTimestamp};

        const SHARD: ShardId = ShardId::ROOT;

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
            fork_header(SHARD, height, round, parent_block_hash, salt)
        }

        /// Pair a header with a genuine quorum QC signed by `committee`.
        fn certify(committee: &TestCommittee, header: BlockHeader) -> CertifiedBlockHeader {
            certify_header(committee, header, &committee.quorum_indices())
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
            direct_commit_proof(committee, SHARD, height, round, parent, salt)
        }

        /// Two committed branches at one height with distinct hashes.
        fn conflicting_commits(committee: &TestCommittee) -> ShardForkProof {
            let parent = BlockHash::from_raw(Hash::from_bytes(b"fork-parent"));
            ShardForkProof::ConflictingCommits {
                a: direct_proof(committee, BlockHeight::new(9), Round::new(9), parent, 1),
                b: direct_proof(committee, BlockHeight::new(9), Round::new(11), parent, 2),
            }
        }

        /// A block's committee anchors on its parent, so the committee that
        /// signed a QC over block `h` is the one at `h-1`'s anchor — not
        /// `h`'s own. A committee that forks chooses when to do it, so a
        /// boundary is exactly where it would aim: resolving on the block's
        /// own anchor hands it a window where its evidence never verifies and
        /// the fence never fires.
        #[test]
        fn each_qcs_committee_resolves_at_the_signing_window() {
            const ED: u64 = 1_000;
            let committee = TestCommittee::new(4, 21);

            // Two windows, distinguishable by committee size: epoch 0 seats
            // four, epoch 1 seats three.
            let epoch0 = Arc::new(committee.topology_snapshot(1));
            let epoch1 = Arc::new(TestCommittee::new(3, 22).topology_snapshot(1));
            let mut sched = TopologySchedule::new(ED, Epoch::new(1), Arc::clone(&epoch1));
            sched.insert(Epoch::new(0), Arc::clone(&epoch0));

            // The certified block's parent anchors below the cut; the block
            // itself above it. So `certified`'s QC was signed by epoch 0 and
            // `child`'s by epoch 1 — one proof spanning both.
            let below = WeightedTimestamp::from_millis(ED - 1);
            let above = WeightedTimestamp::from_millis(ED + 1);
            let certified_parent = live_fork_header(
                SHARD,
                BlockHeight::new(7),
                Round::new(7),
                BlockHash::ZERO,
                below,
                1,
            );
            let certified_header = live_fork_header(
                SHARD,
                BlockHeight::new(8),
                Round::new(8),
                certified_parent.hash(),
                above,
                2,
            );
            let child_header = live_fork_header(
                SHARD,
                BlockHeight::new(9),
                Round::new(9),
                certified_header.hash(),
                above,
                3,
            );
            let proof = CommitProof::direct(
                CertifiedBlockHeader::new(certified_header, anchor_qc(SHARD, above)),
                CertifiedBlockHeader::new(child_header, anchor_qc(SHARD, above)),
                Some(certified_parent),
            );
            let fork = ShardForkProof::ConflictingCommits {
                a: proof.clone(),
                b: proof,
            };

            let resolved = fork
                .resolve_committees(&sched)
                .expect("both windows are in the schedule");
            assert_eq!(
                (resolved[0].public_keys.len(), resolved[1].public_keys.len()),
                (4, 3),
                "the certified block's QC resolves in its parent's window, its child's in its own",
            );
        }

        #[test]
        fn direct_fork_assembles_and_verifies() {
            let committee = TestCommittee::new(4, 1);
            let proof = conflicting_commits(&committee);
            assert_eq!(proof.verify(&BlsVerifier, &schedule(&committee)), Ok(()));
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
                proof.verify(&BlsVerifier, &schedule(&committee)),
                Err(ShardForkProofVerifyError::NotConflicting)
            );
        }

        #[test]
        fn wrong_committee_fails_bls() {
            let committee = TestCommittee::new(4, 3);
            let proof = conflicting_commits(&committee);
            // Verify against a different committee's keys.
            let other = TestCommittee::new(4, 999);
            let err = proof.verify(&BlsVerifier, &schedule(&other)).unwrap_err();
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
            let block_parent = header(BlockHeight::new(4), Round::new(4), parent, 9);
            let block = certify(
                &committee,
                header(BlockHeight::new(5), Round::new(5), block_parent.hash(), 1),
            );
            // Child at round+2, not round+1 — a valid QC but no direct commit.
            let child = certify(
                &committee,
                header(BlockHeight::new(6), Round::new(7), block.block_hash(), 2),
            );
            let good = direct_proof(&committee, BlockHeight::new(5), Round::new(5), parent, 3);
            let proof = ShardForkProof::ConflictingCommits {
                a: CommitProof::direct(block, child, Some(block_parent)),
                b: good,
            };
            assert_eq!(
                proof.verify(&BlsVerifier, &schedule(&committee)),
                Err(ShardForkProofVerifyError::ProofA(
                    CommitProofVerifyError::NotRoundContiguous
                ))
            );
        }

        #[test]
        fn child_not_extending_parent_rejected() {
            let committee = TestCommittee::new(4, 5);
            let parent = BlockHash::from_raw(Hash::from_bytes(b"p"));
            let block_parent = header(BlockHeight::new(4), Round::new(4), parent, 9);
            let block = certify(
                &committee,
                header(BlockHeight::new(5), Round::new(5), block_parent.hash(), 1),
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
                a: CommitProof::direct(block, child, Some(block_parent)),
                b: direct_proof(&committee, BlockHeight::new(5), Round::new(5), parent, 3),
            };
            assert_eq!(
                proof.verify(&BlsVerifier, &schedule(&committee)),
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
            let a = CommitProof::new(d, child, Some(b.clone()), Capped::from_array([b.clone()]));
            assert_eq!(a.proven_height(), BlockHeight::new(8));
            assert_eq!(a.proven_block_hash(), b.hash());

            let other = direct_proof(&committee, BlockHeight::new(8), Round::new(8), parent, 99);
            let fork = ShardForkProof::ConflictingCommits { a, b: other };
            assert_eq!(fork.verify(&BlsVerifier, &schedule(&committee)), Ok(()));
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
                proof.verify(&BlsVerifier, &schedule),
                Err(ShardForkProofVerifyError::CommitteeUnresolved)
            );
        }

        #[test]
        fn fork_proof_hbor_round_trip() {
            let committee = TestCommittee::new(4, 10);
            let proof = conflicting_commits(&committee);
            let bytes = hbor_to_vec(&proof).unwrap();
            let decoded: ShardForkProof = hbor_from_slice(&bytes).unwrap();
            assert_eq!(proof, decoded);
        }
    }
}
