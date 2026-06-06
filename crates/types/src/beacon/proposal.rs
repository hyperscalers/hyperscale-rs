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
    Bls12381G1PrivateKey, Bls12381G1PublicKey, BoundedVec, Epoch, MAX_EQUIVOCATIONS_PER_PROPOSER,
    MAX_SHARD_WITNESSES_PER_PROPOSER, NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcValueElement,
    PcVoteEquivocation, ShardWitness, Verifiable, Verified, Verify, VrfOutput, VrfProof,
    vrf_output_from_proof, vrf_sign, vrf_verify,
};

/// One committee member's slot submission.
///
/// Field-level validation (VRF proof verifies under the signer's
/// pubkey against the `(network.id, slot)` message, witnesses dedup
/// against the per-shard high-water marks, etc.) is the beacon
/// crate's job — this is a pure data container.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconProposal {
    shard_witnesses: BoundedVec<Verifiable<ShardWitness>, MAX_SHARD_WITNESSES_PER_PROPOSER>,
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
    /// Panics if either list exceeds its per-proposer cap.
    #[must_use]
    pub fn new(
        shard_witnesses: Vec<ShardWitness>,
        equivocations: Vec<PcVoteEquivocation>,
        vrf_proof: VrfProof,
    ) -> Self {
        Self {
            shard_witnesses: shard_witnesses
                .into_iter()
                .map(Verifiable::from)
                .collect::<Vec<_>>()
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
            shard_witnesses: BoundedVec::new(),
            equivocations: BoundedVec::new(),
            vrf_proof,
        }
    }

    /// Shard witnesses lifted from source committees this slot. Each
    /// rides as `Verifiable<ShardWitness>`: wire-decoded proposals land
    /// `Unverified`; the beacon admission gate upgrades the marker.
    #[must_use]
    pub const fn shard_witnesses(
        &self,
    ) -> &BoundedVec<Verifiable<ShardWitness>, MAX_SHARD_WITNESSES_PER_PROPOSER> {
        &self.shard_witnesses
    }

    /// Equivocation evidence observed this slot. Same `Verifiable`
    /// lifecycle as [`Self::shard_witnesses`]; admission jails the named
    /// validator once the block commits.
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
    /// across epochs as the same PC element. The fallback rehash avoids
    /// accidental collision with [`HASH_BOTTOM`] (the "no proposal"
    /// sentinel): if the natural digest happens to land on all-zeros,
    /// a tag-prefixed rehash moves it elsewhere while preserving
    /// collision resistance against other inputs.
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
        if raw == [0u8; PC_VALUE_ELEMENT_BYTES] {
            let mut rehash = Hasher::new();
            rehash.update(COLLISION_DOMAIN);
            rehash.update(&raw);
            raw.copy_from_slice(rehash.finalize().as_bytes());
        }
        PcValueElement::new(raw)
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

/// The witness lists handed to
/// [`Verified::<BeaconProposal>::with_verified_witnesses`] aren't
/// content-identical to the proposal's own — a marker rebind must not
/// substitute witnesses.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("witness rebind content mismatch")]
pub struct BeaconProposalWitnessMismatch;

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
    /// Panics if either list exceeds its per-proposer cap (inherited
    /// from [`BeaconProposal::new`]).
    #[must_use]
    pub fn sign_local(
        sk: &Bls12381G1PrivateKey,
        network: &NetworkDefinition,
        epoch: Epoch,
        shard_witnesses: Vec<ShardWitness>,
        equivocations: Vec<PcVoteEquivocation>,
    ) -> Self {
        let vrf_proof = vrf_sign(sk, network, epoch);
        Self::new_unchecked(BeaconProposal::new(
            shard_witnesses,
            equivocations,
            vrf_proof,
        ))
    }

    /// Rebind the proposal's witness lists to their marker-upgraded
    /// forms. The supplied lists must be content-identical to the
    /// proposal's own (`Verifiable` compares by raw `T`, so only the
    /// verification markers may differ); the VRF predicate already
    /// established on `self` covers `(network, epoch)` only and is
    /// unaffected, so the rebind is sound by construction.
    ///
    /// Mirrors [`Verified::<BlockHeader>::with_verified_parent_qc`].
    ///
    /// # Errors
    ///
    /// Returns [`BeaconProposalWitnessMismatch`] if either supplied list
    /// isn't content-identical to the proposal's own — a rebind must
    /// upgrade markers, never substitute witnesses.
    pub fn with_verified_witnesses(
        self,
        shard_witnesses: BoundedVec<Verifiable<ShardWitness>, MAX_SHARD_WITNESSES_PER_PROPOSER>,
        equivocations: BoundedVec<Verifiable<PcVoteEquivocation>, MAX_EQUIVOCATIONS_PER_PROPOSER>,
    ) -> Result<Self, BeaconProposalWitnessMismatch> {
        if self.shard_witnesses() != &shard_witnesses || self.equivocations() != &equivocations {
            return Err(BeaconProposalWitnessMismatch);
        }
        Ok(Self::new_unchecked(BeaconProposal {
            shard_witnesses,
            equivocations,
            ..self.into_inner()
        }))
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, Categorize as _, DecodeError,
        Encoder as _, NoCustomValueKind, ValueKind, VecEncoder,
    };

    use super::*;
    use crate::{
        BlockHash, LeafIndex, ShardGroupId, ShardWitness, ShardWitnessPayload, ShardWitnessProof,
        Stake, StakePoolId,
    };

    fn sample_witness(leaf_index: u64) -> ShardWitness {
        ShardWitness {
            payload: ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(1),
                amount: Stake::from_whole_tokens(1_000),
            },
            proof: ShardWitnessProof {
                shard_id: ShardGroupId::ROOT,
                committed_block_hash: BlockHash::ZERO,
                leaf_index: LeafIndex::new(leaf_index),
                siblings: Vec::new().into(),
            },
        }
    }

    fn sample_proposal() -> BeaconProposal {
        BeaconProposal::new(
            vec![sample_witness(0), sample_witness(1), sample_witness(2)],
            Vec::new(),
            VrfProof::new([0xCD; 96]),
        )
    }

    #[test]
    fn sbor_round_trip() {
        let original = sample_proposal();
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconProposal = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn vrf_only_has_no_witnesses() {
        let p = BeaconProposal::vrf_only(VrfProof::ZERO);
        assert!(p.shard_witnesses().is_empty());
        assert!(p.equivocations().is_empty());
        assert_eq!(p.vrf_proof(), VrfProof::ZERO);
        // Output is derived from the proof, not the all-zero sentinel.
        assert_eq!(p.vrf_output(), vrf_output_from_proof(&VrfProof::ZERO));
    }

    /// Hand-roll a `BeaconProposal` whose `shard_witnesses` length
    /// prefix exceeds the cap. The `BoundedVec` decoder fires before
    /// any per-element work happens.
    #[test]
    fn decode_rejects_oversized_witness_count() {
        let proposal = sample_proposal();
        let mut buf = Vec::with_capacity(256);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            // BeaconProposal has 3 fields.
            enc.write_size(3).unwrap();
            // Oversized shard-witnesses array (the first field).
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ShardWitness::value_kind()).unwrap();
            enc.write_size(MAX_SHARD_WITNESSES_PER_PROPOSER + 1)
                .unwrap();
            // Don't bother writing the rest — decode fails on the count.
            let _ = &proposal;
        }
        let err = basic_decode::<BeaconProposal>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_SHARD_WITNESSES_PER_PROPOSER
                    && actual == MAX_SHARD_WITNESSES_PER_PROPOSER + 1
        ));
    }

    #[test]
    fn accessors_return_built_values() {
        let p = sample_proposal();
        assert_eq!(p.shard_witnesses().len(), 3);
        assert!(p.equivocations().is_empty());
        assert_eq!(p.vrf_proof(), VrfProof::new([0xCD; 96]));
        // Output is derived from the proof.
        assert_eq!(
            p.vrf_output(),
            vrf_output_from_proof(&VrfProof::new([0xCD; 96]))
        );
    }

    #[test]
    fn with_verified_witnesses_rebinds_equal_content_and_rejects_substitution() {
        let verified = Verified::new_unchecked_for_test(sample_proposal());
        // Content-equal lists (markers may differ) rebind cleanly.
        let same_shard = verified.shard_witnesses().clone();
        let same_equiv = verified.equivocations().clone();
        assert!(
            verified
                .clone()
                .with_verified_witnesses(same_shard, same_equiv)
                .is_ok()
        );
        // Substituting a different witness is rejected — a rebind must
        // upgrade markers, never swap content.
        let substituted: BoundedVec<_, MAX_SHARD_WITNESSES_PER_PROPOSER> =
            vec![Verifiable::from(sample_witness(99))].into();
        assert_eq!(
            verified.with_verified_witnesses(substituted, BoundedVec::new()),
            Err(BeaconProposalWitnessMismatch),
        );
    }

    #[test]
    fn pc_element_hash_differs_across_epochs() {
        let p = sample_proposal();
        let h1 = p.pc_element_hash(Epoch::new(1));
        let h2 = p.pc_element_hash(Epoch::new(2));
        assert_ne!(h1, h2);
    }

    /// `HASH_BOTTOM` is the all-zero sentinel for "no proposal from
    /// this validator". `pc_element_hash`'s rehash must guarantee no
    /// real proposal lands on it.
    #[test]
    fn pc_element_hash_avoids_all_zero() {
        let p = sample_proposal();
        let h = p.pc_element_hash(Epoch::new(1));
        assert_ne!(h, PcValueElement::new([0u8; PC_VALUE_ELEMENT_BYTES]));
    }
}
