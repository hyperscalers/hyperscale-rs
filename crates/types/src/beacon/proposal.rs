//! [`BeaconProposal`] — what one committee member submits per slot.
//!
//! Each member's proposal carries (1) shard witnesses lifted from
//! source committees, (2) equivocation evidence observed locally, and
//! (3) a VRF reveal for the slot. Once SPC produces an `OutputHigh` for
//! the slot, every accepted proposal lands in the resulting
//! [`BeaconBlock::committed_proposals`](crate::BeaconBlock).

use blake3::Hasher;
use sbor::prelude::*;
use thiserror::Error;

use crate::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, BoundedBTreeMap, BoundedVec, Epoch,
    MAX_EQUIVOCATIONS_PER_PROPOSER, MAX_SHARDS, NetworkDefinition, PC_VALUE_ELEMENT_BYTES,
    PcValueElement, PcVoteEquivocation, QuorumCertificate, ShardId, Verifiable, Verified, Verify,
    VrfOutput, VrfProof, vrf_output_from_proof, vrf_sign, vrf_verify,
};

/// One committee member's slot submission.
///
/// Field-level validation (VRF proof verifies under the signer's
/// pubkey against the `(network.id, slot)` message, witnesses dedup
/// against the per-shard high-water marks, etc.) is the beacon
/// crate's job — this is a pure data container.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconProposal {
    /// This proposer's view of where each live shard's chain sits at the
    /// epoch boundary: the **canonical** boundary QC per shard (the
    /// `parent_qc` of the boundary block's committed child), or `None`
    /// for a live shard whose crossing this proposer hasn't yet observed.
    /// One honest reporter is enough to mark a shard live, so partial
    /// coverage is fine.
    boundary_qcs: BoundedBTreeMap<ShardId, Option<Verifiable<QuorumCertificate>>, MAX_SHARDS>,
    equivocations: BoundedVec<Verifiable<PcVoteEquivocation>, MAX_EQUIVOCATIONS_PER_PROPOSER>,
    /// The VRF proof for this slot. The output is `vrf_output()`, a pure
    /// function of the proof — never stored, so it can't disagree.
    vrf_proof: VrfProof,
}

impl BeaconProposal {
    /// Build a `BeaconProposal` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if any list or map exceeds its per-proposer cap.
    #[must_use]
    pub fn new(
        boundary_qcs: BTreeMap<ShardId, Option<QuorumCertificate>>,
        equivocations: Vec<PcVoteEquivocation>,
        vrf_proof: VrfProof,
    ) -> Self {
        Self {
            boundary_qcs: boundary_qcs
                .into_iter()
                .map(|(shard, qc)| (shard, qc.map(Verifiable::from)))
                .collect::<BTreeMap<_, _>>()
                .into(),
            equivocations: equivocations
                .into_iter()
                .map(Verifiable::from)
                .collect::<Vec<_>>()
                .into(),
            vrf_proof,
        }
    }

    /// Empty proposal — no observations, carrying only the given VRF
    /// reveal. Useful for committee members with nothing to observe in
    /// a given slot.
    #[must_use]
    pub const fn vrf_only(vrf_proof: VrfProof) -> Self {
        Self {
            boundary_qcs: BoundedBTreeMap::new(),
            equivocations: BoundedVec::new(),
            vrf_proof,
        }
    }

    /// Per-shard canonical boundary QCs this proposer observed (or `None`
    /// for a live shard it hasn't seen cross). Each rides as
    /// `Verifiable<QuorumCertificate>`: wire-decoded proposals land
    /// `Unverified`; the fold verifies them against the shard committee.
    #[must_use]
    pub const fn boundary_qcs(
        &self,
    ) -> &BoundedBTreeMap<ShardId, Option<Verifiable<QuorumCertificate>>, MAX_SHARDS> {
        &self.boundary_qcs
    }

    /// Equivocation evidence observed this slot. Each entry carries a
    /// `Verifiable` marker upgraded at the admission gate; admission jails
    /// the named validator once the block commits.
    #[must_use]
    pub const fn equivocations(
        &self,
    ) -> &BoundedVec<Verifiable<PcVoteEquivocation>, MAX_EQUIVOCATIONS_PER_PROPOSER> {
        &self.equivocations
    }

    /// VRF output for this slot — `BLAKE3` of the proof, mixed into
    /// beacon randomness once the committee commits to the slot's
    /// proposal set. Derived on demand from [`Self::vrf_proof`], so it
    /// can never disagree with the proof.
    #[must_use]
    pub fn vrf_output(&self) -> VrfOutput {
        vrf_output_from_proof(&self.vrf_proof)
    }

    /// VRF proof — verifiable under the proposer's pubkey against the
    /// `(network.id, slot)` message.
    #[must_use]
    pub const fn vrf_proof(&self) -> VrfProof {
        self.vrf_proof
    }

    /// Hash this proposal into the `PcValueElement` that represents it
    /// in the epoch's SPC input vector.
    ///
    /// `epoch` is bound into the digest so a proposal can't be replayed
    /// across epochs as the same PC element.
    /// [`PcValueElement::from_digest`] keeps the result off the
    /// [`PcValueElement::BOTTOM`] "no proposal" sentinel.
    ///
    /// # Panics
    ///
    /// Never in practice: every field is `BasicSbor` and the struct is
    /// closed, so encoding is total.
    #[must_use]
    pub fn pc_element_hash(&self, epoch: Epoch) -> PcValueElement {
        const DOMAIN: &[u8] = b"hyperscale-beacon-proposal-v1";
        const COLLISION_DOMAIN: &[u8] = b"hyperscale-beacon-proposal-bottom-collision-v1";
        let encoded = basic_encode(self).expect("BeaconProposal SBOR encoding is infallible");
        let mut hasher = Hasher::new();
        hasher.update(DOMAIN);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&encoded);
        let mut raw = [0u8; PC_VALUE_ELEMENT_BYTES];
        raw.copy_from_slice(hasher.finalize().as_bytes());
        PcValueElement::from_digest(raw, COLLISION_DOMAIN)
    }
}

// ─── Typestate ─────────────────────────────────────────────────────────────

/// Verification context for [`BeaconProposal`].
///
/// VRF reveal verification is bound to `(network, epoch)` and checks
/// against the proposer's pubkey. The coordinator resolves `sender_pk`
/// from `BeaconState.validators` before dispatching the verify action.
#[derive(Debug, Clone, Copy)]
pub struct BeaconProposalVerifyContext<'a> {
    /// Network the proposer was bound to.
    pub network: &'a NetworkDefinition,
    /// Epoch the proposal targets — mixed into the VRF reveal's signing
    /// bytes.
    pub epoch: Epoch,
    /// Proposer's BLS public key — the VRF reveal verifies under this.
    pub sender_pk: Bls12381G1PublicKey,
}

/// Failure modes of a beacon proposal.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BeaconProposalVerifyError {
    /// VRF reveal did not verify under `sender_pk` over `(network, epoch)`.
    #[error("VRF reveal did not verify")]
    BadVrfReveal,
}

/// An equivocation marker rebind tried to substitute evidence.
///
/// Returned when the list handed to
/// [`Verified::<BeaconProposal>::with_verified_equivocations`] isn't
/// content-identical to the proposal's own — a rebind must upgrade
/// markers, never swap the underlying evidence.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("equivocation rebind content mismatch")]
pub struct BeaconProposalEquivocationMismatch;

impl Verify<&BeaconProposalVerifyContext<'_>> for BeaconProposal {
    type Error = BeaconProposalVerifyError;

    /// Beacon-proposal predicate: VRF reveal verifies under
    /// `sender_pk` over `(network, epoch)`. Witness-level validity
    /// (shard merkle proofs, embedded equivocations) lives at the
    /// `CertifiedBeaconBlock` boundary and isn't part of this
    /// predicate.
    fn verify(&self, ctx: &BeaconProposalVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        if !vrf_verify(&ctx.sender_pk, ctx.network, ctx.epoch, &self.vrf_proof) {
            return Err(BeaconProposalVerifyError::BadVrfReveal);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

// ─── Named gates ────────────────────────────────────────────────────────────

impl Verified<BeaconProposal> {
    /// Sign a beacon proposal locally — derive the VRF reveal under
    /// the signer's key, pair it with the proposer's observations, and
    /// produce a `Verified<BeaconProposal>` whose VRF predicate holds by
    /// construction.
    ///
    /// # Panics
    ///
    /// Panics if any list or map exceeds its per-proposer cap (inherited
    /// from [`BeaconProposal::new`]).
    #[must_use]
    pub fn sign_local(
        sk: &Bls12381G1PrivateKey,
        network: &NetworkDefinition,
        epoch: Epoch,
        boundary_qcs: BTreeMap<ShardId, Option<QuorumCertificate>>,
        equivocations: Vec<PcVoteEquivocation>,
    ) -> Self {
        let vrf_proof = vrf_sign(sk, network, epoch);
        Self::new_unchecked(BeaconProposal::new(boundary_qcs, equivocations, vrf_proof))
    }

    /// Rebind the proposal's equivocation list to its marker-upgraded
    /// form. The supplied list must be content-identical to the proposal's
    /// own (`Verifiable` compares by raw `T`, so only the verification
    /// markers may differ); the VRF predicate already established on
    /// `self` covers `(network, epoch)` only and is unaffected, so the
    /// rebind is sound by construction.
    ///
    /// Mirrors [`Verified::<BlockHeader>::with_verified_parent_qc`].
    ///
    /// # Errors
    ///
    /// Returns [`BeaconProposalEquivocationMismatch`] if the supplied list
    /// isn't content-identical to the proposal's own — a rebind must
    /// upgrade markers, never substitute evidence.
    pub fn with_verified_equivocations(
        self,
        equivocations: BoundedVec<Verifiable<PcVoteEquivocation>, MAX_EQUIVOCATIONS_PER_PROPOSER>,
    ) -> Result<Self, BeaconProposalEquivocationMismatch> {
        if self.equivocations() != &equivocations {
            return Err(BeaconProposalEquivocationMismatch);
        }
        Ok(Self::new_unchecked(BeaconProposal {
            equivocations,
            ..self.into_inner()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ChainOrigin, PcValueElement, PcVector, PcVoteRound, ShardId, SpcView, ValidatorId,
        zero_bls_signature,
    };

    fn sample_boundary_qcs() -> BTreeMap<ShardId, Option<QuorumCertificate>> {
        std::iter::once((
            ShardId::ROOT,
            Some(QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT)),
        ))
        .collect()
    }

    /// A structurally well-formed (but cryptographically empty)
    /// equivocation — `with_verified_equivocations` compares content, not
    /// validity, so a zero-signature placeholder is enough to exercise the
    /// rebind/reject paths.
    fn sample_equivocation() -> PcVoteEquivocation {
        let value_a = PcVector::new([PcValueElement::new([0xAA; 32])]);
        let value_b = PcVector::new([PcValueElement::new([0xBB; 32])]);
        PcVoteEquivocation {
            validator: ValidatorId::new(0),
            epoch: Epoch::new(1),
            view: SpcView::new(0),
            round: PcVoteRound::Vote1,
            value_a,
            sig_a: zero_bls_signature(),
            value_b,
            sig_b: zero_bls_signature(),
        }
    }

    fn sample_proposal() -> BeaconProposal {
        BeaconProposal::new(sample_boundary_qcs(), Vec::new(), VrfProof::new([0xCD; 96]))
    }

    #[test]
    fn sbor_round_trip() {
        let original = sample_proposal();
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconProposal = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn vrf_only_is_empty() {
        let p = BeaconProposal::vrf_only(VrfProof::ZERO);
        assert!(p.boundary_qcs().is_empty());
        assert!(p.equivocations().is_empty());
        assert_eq!(p.vrf_proof(), VrfProof::ZERO);
        // Output is derived from the proof, not the all-zero sentinel.
        assert_eq!(p.vrf_output(), vrf_output_from_proof(&VrfProof::ZERO));
    }

    #[test]
    fn accessors_return_built_values() {
        let p = sample_proposal();
        assert_eq!(p.boundary_qcs().len(), 1);
        assert!(p.equivocations().is_empty());
        assert_eq!(p.vrf_proof(), VrfProof::new([0xCD; 96]));
        // Output is derived from the proof.
        assert_eq!(
            p.vrf_output(),
            vrf_output_from_proof(&VrfProof::new([0xCD; 96]))
        );
    }

    #[test]
    fn with_verified_equivocations_rebinds_equal_content_and_rejects_substitution() {
        let proposal = BeaconProposal::new(
            sample_boundary_qcs(),
            vec![sample_equivocation()],
            VrfProof::new([0xCD; 96]),
        );
        let verified = Verified::new_unchecked_for_test(proposal);
        // Content-equal list (markers may differ) rebinds cleanly.
        let same = verified.equivocations().clone();
        assert!(verified.clone().with_verified_equivocations(same).is_ok());
        // Substituting different evidence is rejected — a rebind must
        // upgrade markers, never swap content.
        let substituted: BoundedVec<_, MAX_EQUIVOCATIONS_PER_PROPOSER> = BoundedVec::new();
        assert_eq!(
            verified.with_verified_equivocations(substituted),
            Err(BeaconProposalEquivocationMismatch),
        );
    }

    #[test]
    fn pc_element_hash_differs_across_epochs() {
        let p = sample_proposal();
        let h1 = p.pc_element_hash(Epoch::new(1));
        let h2 = p.pc_element_hash(Epoch::new(2));
        assert_ne!(h1, h2);
    }

    /// `PcValueElement::BOTTOM` is the all-zero sentinel for "no proposal from
    /// this validator". `pc_element_hash`'s rehash must guarantee no
    /// real proposal lands on it.
    #[test]
    fn pc_element_hash_avoids_all_zero() {
        let p = sample_proposal();
        let h = p.pc_element_hash(Epoch::new(1));
        assert_ne!(h, PcValueElement::new([0u8; PC_VALUE_ELEMENT_BYTES]));
    }
}
