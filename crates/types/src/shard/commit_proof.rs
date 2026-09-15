//! Commitment evidence: proof that a block committed on its shard.
//!
//! A quorum certificate proves *availability*, not canonicality — an
//! f+1..2f committee can certify two blocks at one height without any
//! validator breaking the safe-vote rule. [`CommitProof`] carries the
//! committing *structure* a bare QC cannot forge: a round-contiguous
//! two-chain, which is the HotStuff-2 direct-commit rule, plus a bounded
//! parent-hash ancestry link for a block that committed only as the prefix
//! of a later two-chain after a view change (INV-SHARD-4).
//!
//! Not itself evidence of misbehaviour. Consumers span the adversarial and
//! the ordinary: [`ShardForkProof`] pairs
//! two conflicting proofs into a fork accusation, remote-header
//! consumption marks heights commit-proven, and a split child's follower
//! establishes that the parent's terminal block committed before deriving
//! its genesis from it.
//!
//! [`ShardForkProof`]: super::evidence::ShardForkProof

use hyperscale_crypto::Verifier;
use hyperscale_hbor::Hbor;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeader, BlockHeight, CertifiedBlockHeader, ConsensusPublicKey,
    NetworkDefinition, QcContext, QcVerifyError, ShardId, Verify, VoteCount, WeightedTimestamp,
};

/// Cap on a [`CommitProof`]'s ancestry-link length.
///
/// A block commits as the prefix of a later two-chain only across a
/// bounded view-change gap (INV-SHARD-4), so the parent-hash link from the
/// directly-committed block down to the proven block is short: a link of
/// `k` needs `k` consecutive heights that each failed to commit directly,
/// and rounds rise per block, so every one of them costs a skipped round —
/// `2k` rounds without a single round-contiguous pair.
///
/// The same number bounds the producer, the wire, and the verifier. A
/// producer abandons a run past it (`reshape::observer`), decode refuses a
/// longer link before allocating for it, and
/// [`verify_structure`](CommitProof::verify_structure) refuses one built
/// locally. Erring generous is the safe direction: a cap under what an
/// honest run reaches makes a real fork unprovable, and a fence that never
/// engages is the failure that costs safety rather than bytes.
pub const MAX_COMMIT_PROOF_ANCESTRY: usize = 256;

/// A committee resolved for one QC in a [`CommitProof`].
///
/// Signer public keys in committee (bitfield) order, plus the quorum
/// threshold. Produced by [`ShardForkProof::resolve_committees`] from the
/// topology schedule so an off-thread verifier
/// ([`ShardForkProof::verify_resolved`]) runs the signature work without the
/// schedule in hand — the same emitter-resolves pattern the beacon-block
/// verify action uses.
///
/// [`ShardForkProof::resolve_committees`]: super::evidence::ShardForkProof::resolve_committees
///
/// [`ShardForkProof::verify_resolved`]: super::evidence::ShardForkProof::verify_resolved
#[derive(Debug, Clone)]
pub struct ResolvedCommittee {
    /// Committee public keys, positionally aligned to the QC's signer
    /// bitfield.
    pub public_keys: Vec<ConsensusPublicKey>,
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
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct CommitProof {
    /// Lower block of the committing two-chain — directly committed by
    /// [`Self::child`]. The proven block when [`Self::ancestry`] is empty.
    certified: CertifiedBlockHeader,
    /// Round-contiguous child that commits [`Self::certified`].
    child: CertifiedBlockHeader,
    /// [`Self::certified`]'s parent — carried because a block's committee
    /// anchors on its parent, so this header is what resolves the committee
    /// that signed `certified`'s QC. A fork-evidence verifier holds no part
    /// of the accused shard's chain, so only the proof can supply it.
    ///
    /// Pinned by `certified.header().parent_block_hash()`, which is also
    /// what the [`Self::ancestry`] walk pins its first link to — so a
    /// non-empty ancestry names this same header, and neither can be
    /// substituted to steer committee resolution.
    ///
    /// `None` where the producer cannot reach it: the reshape handoff proves
    /// a terminal sitting directly above a snap-sync anchor, whose header it
    /// never receives. That consumer resolves its own committee (one window
    /// covers the whole two-chain) and never asks. Fork evidence does ask,
    /// and a proof that cannot answer is dropped rather than verified against
    /// a guess.
    certified_parent: Option<BlockHeader>,
    /// Parent-hash header chain from [`Self::certified`]'s parent down to
    /// the proven block; empty when `certified` is itself the proven
    /// block. `ancestry[0]` is `certified`'s parent; `ancestry[i].hash()
    /// == ancestry[i-1].parent_block_hash()`; the last element is the
    /// proven block.
    #[hbor(max = MAX_COMMIT_PROOF_ANCESTRY)]
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
    /// The carried `certified_parent` is not the header `certified` names as
    /// its parent, so it cannot resolve `certified`'s committee.
    #[error("commit proof certified-parent header does not match")]
    ParentMismatch,
    /// An ancestry link's hash or height does not chain down from
    /// `certified`.
    #[error("commit proof ancestry link is broken")]
    AncestryBroken,
    /// The ancestry link exceeds [`MAX_COMMIT_PROOF_ANCESTRY`].
    #[error("commit proof ancestry link is too long")]
    AncestryTooLong,
    /// A member QC failed signature verification against its committee.
    #[error("commit proof QC verification failed: {0}")]
    Qc(#[from] QcVerifyError),
}

impl CommitProof {
    /// Build a commit proof from a two-chain and its ancestry link.
    #[must_use]
    pub const fn new(
        certified: CertifiedBlockHeader,
        child: CertifiedBlockHeader,
        certified_parent: Option<BlockHeader>,
        ancestry: Vec<BlockHeader>,
    ) -> Self {
        Self {
            certified,
            child,
            certified_parent,
            ancestry,
        }
    }

    /// A direct-commit proof: `certified` is itself the proven block,
    /// committed by its round-contiguous `child`.
    #[must_use]
    pub const fn direct(
        certified: CertifiedBlockHeader,
        child: CertifiedBlockHeader,
        certified_parent: Option<BlockHeader>,
    ) -> Self {
        Self::new(certified, child, certified_parent, Vec::new())
    }

    /// Anchor selecting the committee that signed [`Self::certified`]'s QC —
    /// its parent's own anchor, since a block's committee keys on its parent.
    /// `None` when the proof carries no parent (see
    /// [`Self::certified_parent`]).
    #[must_use]
    pub(crate) fn certified_committee_anchor(&self) -> Option<WeightedTimestamp> {
        Some(
            self.certified_parent
                .as_ref()?
                .parent_qc()
                .weighted_timestamp(),
        )
    }

    /// Anchor selecting the committee that signed [`Self::child`]'s QC — the
    /// certified block's own anchor, one hop up from
    /// [`Self::certified_committee_anchor`].
    #[must_use]
    pub(crate) fn child_committee_anchor(&self) -> WeightedTimestamp {
        self.certified.header().parent_qc().weighted_timestamp()
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
    ///
    /// [`ShardForkProof::resolve_committees`]: super::evidence::ShardForkProof::resolve_committees
    ///
    /// [`ShardForkProof::verify_resolved`]: super::evidence::ShardForkProof::verify_resolved
    pub(crate) const fn qc_headers(&self) -> [&CertifiedBlockHeader; 2] {
        [&self.certified, &self.child]
    }

    /// Structural checks that need no committee: header/QC linkage, the
    /// round-contiguous two-chain shape, and a well-formed ancestry link.
    ///
    /// The full predicate for a consumer whose member headers are already
    /// signature-verified — a proof assembled from locally verified
    /// headers needs no [`Self::verify_resolved`] pass, only the
    /// committing structure a bare QC cannot show.
    ///
    /// # Errors
    ///
    /// A [`CommitProofVerifyError`] naming the failing check.
    pub fn verify_structure(&self) -> Result<(), CommitProofVerifyError> {
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

        // A carried parent is what resolves `certified`'s committee, so it
        // has to be the real one: pin it to the hash `certified` names. The
        // ancestry walk below pins its first link to the same value, so a
        // non-empty ancestry cannot disagree with it.
        if let Some(parent) = &self.certified_parent {
            if parent.shard_id() != self.certified.shard_id() {
                return Err(CommitProofVerifyError::ShardMismatch);
            }
            if parent.hash() != self.certified.header().parent_block_hash()
                || self.certified.height().prev() != Some(parent.height())
            {
                return Err(CommitProofVerifyError::ParentMismatch);
            }
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

    /// Verify this proof standalone: the two-chain's structure, then both
    /// member QCs against their resolved committees (`[certified, child]`,
    /// positionally aligned to the two-chain).
    ///
    /// [`ShardForkProof`] verifies its two member proofs through the same
    /// checks; this is the entry for a consumer holding a single proof —
    /// a split child's follower establishing that the parent's terminal
    /// block *committed* rather than merely certified, which a bare QC
    /// cannot show.
    ///
    /// # Errors
    ///
    /// A [`CommitProofVerifyError`] naming the failing check.
    ///
    /// [`ShardForkProof`]: super::evidence::ShardForkProof
    pub fn verify_resolved(
        &self,
        verifier: &dyn Verifier,
        network: &NetworkDefinition,
        committees: &[ResolvedCommittee; 2],
    ) -> Result<(), CommitProofVerifyError> {
        self.verify_structure()?;
        self.verify_qcs(verifier, network, committees)
    }

    /// Verify both member QCs against their resolved committees.
    /// `committees` is `[certified_committee, child_committee]`.
    pub(crate) fn verify_qcs(
        &self,
        verifier: &dyn Verifier,
        network: &NetworkDefinition,
        committees: &[ResolvedCommittee],
    ) -> Result<(), CommitProofVerifyError> {
        for (ch, committee) in self.qc_headers().into_iter().zip(committees) {
            let ctx = QcContext {
                network,
                public_keys: &committee.public_keys,
                quorum_threshold: committee.quorum_threshold,
                verifier,
            };
            ch.qc().verify(&ctx)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        DecodeError, HborWidth, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use super::*;
    use crate::test_utils::{anchor_qc, fork_header};
    use crate::{BlockHeight, Round, WeightedTimestamp};

    const SHARD: ShardId = ShardId::ROOT;

    fn certified_header(height: u64, round: u64) -> CertifiedBlockHeader {
        let header = fork_header(
            SHARD,
            BlockHeight::new(height),
            Round::new(round),
            BlockHash::ZERO,
            height,
        );
        CertifiedBlockHeader::new(header, anchor_qc(SHARD, WeightedTimestamp::from_millis(1)))
    }

    /// A link past the cap is refused at decode, before the bytes behind it
    /// are read — the producer and the verifier already refuse it, and the
    /// wire is the third party to the same contract.
    #[test]
    fn decode_rejects_oversized_ancestry() {
        let mut buf = hbor_to_vec(&certified_header(5, 5)).unwrap();
        buf.extend_from_slice(&hbor_to_vec(&certified_header(6, 6)).unwrap());
        buf.extend_from_slice(&hbor_to_vec(&Option::<BlockHeader>::None).unwrap());
        varint::write(&mut buf, MAX_COMMIT_PROOF_ANCESTRY + 1).unwrap();
        // Enough bytes behind the claim that the length passes the
        // input-capacity check and the cap is what rejects it.
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_COMMIT_PROOF_ANCESTRY + 1) * BlockHeader::MIN_ENCODED_LEN,
        ));

        let err = hbor_from_slice::<CommitProof>(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                DecodeError::BoundExceeded { max, actual }
                    if max == MAX_COMMIT_PROOF_ANCESTRY
                        && actual == MAX_COMMIT_PROOF_ANCESTRY + 1
            ),
            "expected the ancestry cap to reject, got {err:?}"
        );
    }

    /// And a link at the cap still round-trips, so the bound admits every
    /// proof `verify_structure` would.
    #[test]
    fn ancestry_at_the_cap_round_trips() {
        let ancestry: Vec<BlockHeader> = (0..MAX_COMMIT_PROOF_ANCESTRY)
            .map(|i| {
                fork_header(
                    SHARD,
                    BlockHeight::new(i as u64),
                    Round::new(i as u64),
                    BlockHash::ZERO,
                    i as u64,
                )
            })
            .collect();
        let proof = CommitProof::new(
            certified_header(500, 500),
            certified_header(501, 501),
            None,
            ancestry,
        );

        let bytes = hbor_to_vec(&proof).unwrap();
        let decoded: CommitProof = hbor_from_slice(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }
}
