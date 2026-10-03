//! [`BeaconProposal`] — what one committee member submits per slot.
//!
//! Each member's proposal carries (1) shard witnesses lifted from
//! source committees, (2) equivocation evidence observed locally,
//! (3) a VRF reveal for the slot, and (4) the member's signature over
//! all three. Once SPC produces an `OutputHigh` for
//! the slot, every accepted proposal lands in the resulting
//! [`BeaconBlock::committed_proposals`](crate::BeaconBlock).

use std::collections::BTreeMap;

use blake3::Hasher;
use hyperscale_crypto::{SignError, Signer, Verifier};
use hyperscale_hbor::{Capped, Hbor, to_vec as hbor_to_vec};
use thiserror::Error;

use crate::signing::BeaconProposalMessage;
use crate::{
    ConsensusPublicKey, ConsensusSignature, Epoch, Hash, MAX_EQUIVOCATIONS_PER_PROPOSER,
    MAX_FORK_PROOFS_PER_PROPOSER, MAX_SHARDS, NetworkDefinition, PC_VALUE_ELEMENT_BYTES,
    PcValueElement, PcVoteEquivocation, QuorumCertificate, ShardForkProof, ShardId,
    ShardVoteEquivocation, Verifiable, Verified, Verify, VrfOutput, VrfProof, beacon_reveal_sign,
    beacon_reveal_verify, signed_bytes, vrf_output_from_proof,
};

/// One committee member's slot submission.
///
/// The body carries the proposer's observations and VRF reveal; the
/// body signature binds the proposer to that exact body. Field-level
/// validation (witnesses dedup against the per-shard high-water marks,
/// evidence verifies against the accused, etc.) is the beacon crate's
/// job — [`Verify`] here checks only who authored the proposal.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct BeaconProposal {
    body: ProposalBody,
    /// The proposer's signature over the body, under
    /// [`BeaconProposalMessage`]. Without it the reveal, which any
    /// receiver holds, would authenticate any body a peer paired it with.
    body_sig: ConsensusSignature,
}

/// What a proposal's body signature covers.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct ProposalBody {
    /// This proposer's view of where each live shard's chain sits at the
    /// epoch boundary: the **canonical** boundary QC per shard (the
    /// `parent_qc` of the boundary block's committed child), or `None`
    /// for a live shard whose crossing this proposer hasn't yet observed.
    /// One honest reporter is enough to mark a shard live, so partial
    /// coverage is fine.
    boundary_qcs: Capped<BTreeMap<ShardId, Option<Verifiable<QuorumCertificate>>>, MAX_SHARDS>,
    equivocations: Capped<Vec<Verifiable<PcVoteEquivocation>>, MAX_EQUIVOCATIONS_PER_PROPOSER>,
    /// Self-authenticating fork proofs the proposer has observed, one per
    /// forked shard. Each rides as `Verifiable<Box<ShardForkProof>>`:
    /// wire-decoded proposals land `Unverified`; admission re-verifies
    /// against the topology schedule and the fold stamps a fork-caused
    /// `ShardRecovery` for each shard named here.
    fork_proofs:
        Capped<BTreeMap<ShardId, Verifiable<Box<ShardForkProof>>>, MAX_FORK_PROOFS_PER_PROPOSER>,
    /// Self-authenticating shard double-vote pairs the proposer has
    /// observed via gossip — the recovery lane for evidence whose
    /// holders left the source committee before a proposer there could
    /// drain it into a block. Wire-decoded proposals land `Unverified`;
    /// admission re-verifies each pair against the accused validator's
    /// registered pubkey and the fold convicts the pool.
    vote_equivocations:
        Capped<Vec<Verifiable<Box<ShardVoteEquivocation>>>, MAX_EQUIVOCATIONS_PER_PROPOSER>,
    /// The VRF proof for this slot. The output is `vrf_output()`, a pure
    /// function of the proof — never stored, so it can't disagree.
    vrf_proof: VrfProof,
}

impl ProposalBody {
    fn signing_message(&self, epoch: Epoch) -> BeaconProposalMessage {
        let encoded = hbor_to_vec(self).expect("BeaconProposal HBOR encoding is infallible");
        BeaconProposalMessage {
            epoch,
            body: Hash::from_bytes(&encoded),
        }
    }
}

impl BeaconProposal {
    /// Build an unsigned `BeaconProposal` from its parts. It verifies
    /// only once [`Self::signed`] attaches its author's body signature.
    ///
    /// Each part carries its own cap, so what a proposer observed is
    /// what it may report: an observation past one is dropped rather
    /// than carried into a proposal no committee member would decode.
    #[must_use]
    pub fn new(
        boundary_qcs: BTreeMap<ShardId, Option<QuorumCertificate>>,
        equivocations: Vec<PcVoteEquivocation>,
        fork_proofs: BTreeMap<ShardId, ShardForkProof>,
        vote_equivocations: Vec<ShardVoteEquivocation>,
        vrf_proof: VrfProof,
    ) -> Self {
        let mut proposal = Self::vrf_only(vrf_proof);
        let body = &mut proposal.body;
        for (shard, qc) in boundary_qcs {
            if body
                .boundary_qcs
                .insert(shard, qc.map(Verifiable::from))
                .is_err()
            {
                break;
            }
        }
        for ev in equivocations {
            if body.equivocations.push(Verifiable::from(ev)).is_err() {
                break;
            }
        }
        for (shard, proof) in fork_proofs {
            if body
                .fork_proofs
                .insert(shard, Verifiable::from(Box::new(proof)))
                .is_err()
            {
                break;
            }
        }
        for ev in vote_equivocations {
            if body
                .vote_equivocations
                .push(Verifiable::from(Box::new(ev)))
                .is_err()
            {
                break;
            }
        }
        proposal
    }

    /// Unsigned empty proposal — no observations, carrying only the
    /// given VRF reveal.
    #[must_use]
    pub fn vrf_only(vrf_proof: VrfProof) -> Self {
        Self {
            body: ProposalBody {
                boundary_qcs: Capped::default(),
                equivocations: Capped::empty(),
                fork_proofs: Capped::default(),
                vote_equivocations: Capped::empty(),
                vrf_proof,
            },
            body_sig: ConsensusSignature::ZERO,
        }
    }

    /// Attach `signer`'s body signature for `epoch`, replacing any the
    /// proposal carried.
    ///
    /// # Errors
    ///
    /// Propagates [`SignError`] when the signer cannot sign.
    pub fn signed(
        self,
        signer: &dyn Signer,
        network: &NetworkDefinition,
        epoch: Epoch,
    ) -> Result<Self, SignError> {
        let body_sig = signer.sign(&signed_bytes(&self.body.signing_message(epoch), network))?;
        Ok(Self {
            body: self.body,
            body_sig,
        })
    }

    /// Per-shard canonical boundary QCs this proposer observed (or `None`
    /// for a live shard it hasn't seen cross). Each rides as
    /// `Verifiable<QuorumCertificate>`: wire-decoded proposals land
    /// `Unverified`; the fold verifies them against the shard committee.
    #[must_use]
    pub const fn boundary_qcs(
        &self,
    ) -> &Capped<BTreeMap<ShardId, Option<Verifiable<QuorumCertificate>>>, MAX_SHARDS> {
        &self.body.boundary_qcs
    }

    /// Equivocation evidence observed this slot. Each entry carries a
    /// `Verifiable` marker upgraded at the admission gate; admission jails
    /// the named validator once the block commits.
    #[must_use]
    pub const fn equivocations(
        &self,
    ) -> &Capped<Vec<Verifiable<PcVoteEquivocation>>, MAX_EQUIVOCATIONS_PER_PROPOSER> {
        &self.body.equivocations
    }

    /// Fork proofs observed this slot, keyed by forked shard. Each carries
    /// a `Verifiable` marker; admission re-verifies against the topology
    /// schedule before the proposal enters the pool, and the fold trusts
    /// the committed proof (≥ f+1 honest verifiers stood behind it) to
    /// stamp a fork-caused `ShardRecovery`.
    #[must_use]
    pub const fn fork_proofs(
        &self,
    ) -> &Capped<BTreeMap<ShardId, Verifiable<Box<ShardForkProof>>>, MAX_FORK_PROOFS_PER_PROPOSER>
    {
        &self.body.fork_proofs
    }

    /// Shard double-vote pairs observed via gossip this slot. Each
    /// carries a `Verifiable` marker upgraded at the admission gate;
    /// the fold convicts each named validator's pool once the block
    /// commits.
    #[must_use]
    pub const fn vote_equivocations(
        &self,
    ) -> &Capped<Vec<Verifiable<Box<ShardVoteEquivocation>>>, MAX_EQUIVOCATIONS_PER_PROPOSER> {
        &self.body.vote_equivocations
    }

    /// VRF output for this slot — `BLAKE3` of the proof, mixed into
    /// beacon randomness once the committee commits to the slot's
    /// proposal set. Derived on demand from [`Self::vrf_proof`], so it
    /// can never disagree with the proof.
    #[must_use]
    pub fn vrf_output(&self) -> VrfOutput {
        vrf_output_from_proof(&self.body.vrf_proof)
    }

    /// VRF proof — verifiable under the proposer's pubkey against the
    /// `(network.id, slot)` message.
    #[must_use]
    pub const fn vrf_proof(&self) -> VrfProof {
        self.body.vrf_proof
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
    /// Never for a proposal any construction path produces. Encoding a
    /// capped field past its cap is an error rather than a panic, so the
    /// claim rests on every producer capping what it builds — the
    /// coordinator's equivocation drains and the fork-proof buffer's own
    /// — and on a wire-decoded proposal having cleared the same caps at
    /// decode. A new capped field with no producer-side cap breaks it.
    #[must_use]
    pub fn pc_element_hash(&self, epoch: Epoch) -> PcValueElement {
        const DOMAIN: &[u8] = b"hyperscale-beacon-proposal-v1";
        const COLLISION_DOMAIN: &[u8] = b"hyperscale-beacon-proposal-bottom-collision-v1";
        let encoded = hbor_to_vec(self).expect("BeaconProposal HBOR encoding is infallible");
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
/// The VRF reveal and the body signature are both bound to `(network,
/// epoch)` and check against the proposer's pubkey. The coordinator
/// resolves `sender_pk` from `BeaconState.validators` before dispatching
/// the verify action.
#[derive(Debug, Clone, Copy)]
pub struct BeaconProposalVerifyContext<'a> {
    /// Network the proposer was bound to.
    pub network: &'a NetworkDefinition,
    /// Epoch the proposal targets — mixed into the VRF reveal's signing
    /// bytes.
    pub epoch: Epoch,
    /// Proposer's public key — the VRF reveal and the body signature
    /// verify under this.
    pub sender_pk: ConsensusPublicKey,
    /// Scheme verifier both checks run through.
    pub verifier: &'a dyn Verifier,
}

/// Failure modes of a beacon proposal.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BeaconProposalVerifyError {
    /// VRF reveal did not verify under `sender_pk` over `(network, epoch)`.
    #[error("VRF reveal did not verify")]
    BadVrfReveal,
    /// Body signature did not verify under `sender_pk` over `(network,
    /// epoch, body)`.
    #[error("body signature did not verify")]
    BadBodySignature,
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

    /// Beacon-proposal predicate: the VRF reveal verifies under
    /// `sender_pk` over `(network, epoch)` and the body signature over
    /// `(network, epoch, body)`. Witness-level validity
    /// (shard merkle proofs, embedded equivocations) lives at the
    /// `CertifiedBeaconBlock` boundary and isn't part of this
    /// predicate.
    fn verify(&self, ctx: &BeaconProposalVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        if !beacon_reveal_verify(
            ctx.verifier,
            &ctx.sender_pk,
            ctx.network,
            ctx.epoch,
            &self.body.vrf_proof,
        ) {
            return Err(BeaconProposalVerifyError::BadVrfReveal);
        }
        let msg = signed_bytes(&self.body.signing_message(ctx.epoch), ctx.network);
        if !ctx.verifier.verify(&ctx.sender_pk, &msg, &self.body_sig) {
            return Err(BeaconProposalVerifyError::BadBodySignature);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

// ─── Named gates ────────────────────────────────────────────────────────────

impl Verified<BeaconProposal> {
    /// Sign a beacon proposal locally — derive the VRF reveal under
    /// the signer's key, pair it with the proposer's observations, sign
    /// the resulting body, and produce a `Verified<BeaconProposal>` whose
    /// predicate holds by construction.
    ///
    /// # Errors
    ///
    /// Propagates [`SignError`] when the signer cannot sign.
    pub fn sign_local(
        signer: &dyn Signer,
        network: &NetworkDefinition,
        epoch: Epoch,
        boundary_qcs: BTreeMap<ShardId, Option<QuorumCertificate>>,
        equivocations: Vec<PcVoteEquivocation>,
        fork_proofs: BTreeMap<ShardId, ShardForkProof>,
        vote_equivocations: Vec<ShardVoteEquivocation>,
    ) -> Result<Self, SignError> {
        let vrf_proof = beacon_reveal_sign(signer, network, epoch)?;
        Ok(Self::new_unchecked(
            BeaconProposal::new(
                boundary_qcs,
                equivocations,
                fork_proofs,
                vote_equivocations,
                vrf_proof,
            )
            .signed(signer, network, epoch)?,
        ))
    }

    /// Rebind the proposal's equivocation list to its marker-upgraded
    /// form. The supplied list must be content-identical to the proposal's
    /// own (`Verifiable` compares by raw `T`, so only the verification
    /// markers may differ). `Verifiable` encodes only the raw `T`, so the
    /// body's digest and the signature over it are unaffected, and the
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
        equivocations: Capped<Vec<Verifiable<PcVoteEquivocation>>, MAX_EQUIVOCATIONS_PER_PROPOSER>,
    ) -> Result<Self, BeaconProposalEquivocationMismatch> {
        if self.equivocations() != &equivocations {
            return Err(BeaconProposalEquivocationMismatch);
        }
        let proposal = self.into_inner();
        Ok(Self::new_unchecked(BeaconProposal {
            body: ProposalBody {
                equivocations,
                ..proposal.body
            },
            body_sig: proposal.body_sig,
        }))
    }

    /// Rebind the proposal's vote-equivocation list to its
    /// marker-upgraded form, under the same content-identity rule as
    /// [`Self::with_verified_equivocations`].
    ///
    /// # Errors
    ///
    /// Returns [`BeaconProposalEquivocationMismatch`] if the supplied
    /// list isn't content-identical to the proposal's own.
    pub fn with_verified_vote_equivocations(
        self,
        vote_equivocations: Capped<
            Vec<Verifiable<Box<ShardVoteEquivocation>>>,
            MAX_EQUIVOCATIONS_PER_PROPOSER,
        >,
    ) -> Result<Self, BeaconProposalEquivocationMismatch> {
        if self.vote_equivocations() != &vote_equivocations {
            return Err(BeaconProposalEquivocationMismatch);
        }
        let proposal = self.into_inner();
        Ok(Self::new_unchecked(BeaconProposal {
            body: ProposalBody {
                vote_equivocations,
                ..proposal.body
            },
            body_sig: proposal.body_sig,
        }))
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::{BlsVerifier, signer_from_u64_seed};
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{
        ChainOrigin, PcValueElement, PcVector, PcVoteRound, ShardId, SpcView, ValidatorId,
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
            sig_a: ConsensusSignature::ZERO,
            value_b,
            sig_b: ConsensusSignature::ZERO,
        }
    }

    fn sample_proposal() -> BeaconProposal {
        BeaconProposal::new(
            sample_boundary_qcs(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::new([0xCD; 96]),
        )
    }

    #[test]
    fn hbor_round_trip() {
        let original = sample_proposal();
        let bytes = hbor_to_vec(&original).unwrap();
        let decoded: BeaconProposal = hbor_from_slice(&bytes).unwrap();
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
            BTreeMap::new(),
            Vec::new(),
            VrfProof::new([0xCD; 96]),
        );
        let verified = Verified::new_unchecked_for_test(proposal);
        // Content-equal list (markers may differ) rebinds cleanly.
        let same = verified.equivocations().clone();
        assert!(verified.clone().with_verified_equivocations(same).is_ok());
        // Substituting different evidence is rejected — a rebind must
        // upgrade markers, never swap content.
        let substituted = Vec::new();
        assert_eq!(
            verified.with_verified_equivocations(
                Capped::new(substituted).expect("a list written out in a test")
            ),
            Err(BeaconProposalEquivocationMismatch),
        );
    }

    fn verify_under(
        proposal: &BeaconProposal,
        signer: &dyn Signer,
        epoch: Epoch,
    ) -> Result<Verified<BeaconProposal>, BeaconProposalVerifyError> {
        let network = NetworkDefinition::simulator();
        proposal.verify(&BeaconProposalVerifyContext {
            network: &network,
            epoch,
            sender_pk: signer.public_key(),
            verifier: &BlsVerifier,
        })
    }

    #[test]
    fn a_signed_proposal_verifies_under_its_author() {
        let signer = signer_from_u64_seed(7);
        let network = NetworkDefinition::simulator();
        let epoch = Epoch::new(3);
        let proposal = Verified::<BeaconProposal>::sign_local(
            &signer,
            &network,
            epoch,
            sample_boundary_qcs(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
        )
        .expect("sign")
        .into_inner();
        assert!(verify_under(&proposal, &signer, epoch).is_ok());
        assert_eq!(
            verify_under(&proposal, &signer, Epoch::new(4)).err(),
            Some(BeaconProposalVerifyError::BadVrfReveal),
        );
    }

    /// A peer holding the author's reveal can pair it with a body of its
    /// own choosing; the body signature refuses the pairing.
    #[test]
    fn a_genuine_reveal_on_a_substituted_body_does_not_verify() {
        let signer = signer_from_u64_seed(7);
        let network = NetworkDefinition::simulator();
        let epoch = Epoch::new(3);
        let genuine = Verified::<BeaconProposal>::sign_local(
            &signer,
            &network,
            epoch,
            sample_boundary_qcs(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
        )
        .expect("sign")
        .into_inner();

        let stripped = BeaconProposal::vrf_only(genuine.vrf_proof());
        assert_eq!(
            verify_under(&stripped, &signer, epoch).err(),
            Some(BeaconProposalVerifyError::BadBodySignature),
        );

        let resigned_by_another = BeaconProposal::vrf_only(genuine.vrf_proof())
            .signed(&signer_from_u64_seed(8), &network, epoch)
            .expect("sign");
        assert_eq!(
            verify_under(&resigned_by_another, &signer, epoch).err(),
            Some(BeaconProposalVerifyError::BadBodySignature),
        );
    }

    /// Upgrading markers leaves the signed body's encoding unchanged.
    #[test]
    fn a_marker_rebind_keeps_the_body_signature_valid() {
        let signer = signer_from_u64_seed(7);
        let network = NetworkDefinition::simulator();
        let epoch = Epoch::new(3);
        let proposal = BeaconProposal::new(
            sample_boundary_qcs(),
            vec![sample_equivocation()],
            BTreeMap::new(),
            Vec::new(),
            beacon_reveal_sign(&signer, &network, epoch).expect("sign"),
        )
        .signed(&signer, &network, epoch)
        .expect("sign");
        let verified = verify_under(&proposal, &signer, epoch).expect("verifies");
        let same = verified.equivocations().clone();
        let rebound = verified
            .with_verified_equivocations(same)
            .expect("content equal");
        assert!(verify_under(&rebound.into_inner(), &signer, epoch).is_ok());
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
