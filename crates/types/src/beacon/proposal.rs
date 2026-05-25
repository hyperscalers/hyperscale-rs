//! [`BeaconProposal`] — what one committee member submits per slot.
//!
//! Each member's proposal carries (1) a bounded list of observations
//! ([`Witness`]es lifted from shards) and (2) a VRF reveal for the
//! slot. Once a slot's committee reaches agreement, every accepted
//! proposal becomes a leaf of the slot's `proposals_root` in the
//! resulting [`BeaconBlockHeader`](crate::BeaconBlockHeader).

use blake3::Hasher;
use sbor::prelude::*;

use crate::{
    BoundedVec, Epoch, MAX_WITNESSES_PER_PROPOSER, PC_VALUE_ELEMENT_BYTES, PcValueElement,
    VrfOutput, VrfProof, Witness,
};

/// One committee member's slot submission.
///
/// Field-level validation (VRF proof verifies under the signer's
/// pubkey against the `(network.id, slot)` message, witnesses dedup
/// against the per-shard high-water marks, etc.) is the beacon
/// crate's job — this is a pure data container.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconProposal {
    witnesses: BoundedVec<Witness, MAX_WITNESSES_PER_PROPOSER>,
    vrf_output: VrfOutput,
    vrf_proof: VrfProof,
}

impl BeaconProposal {
    /// Build a `BeaconProposal` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `witnesses.len() > MAX_WITNESSES_PER_PROPOSER`.
    #[must_use]
    pub fn new(witnesses: Vec<Witness>, vrf_output: VrfOutput, vrf_proof: VrfProof) -> Self {
        Self {
            witnesses: witnesses.into(),
            vrf_output,
            vrf_proof,
        }
    }

    /// Empty proposal — no witnesses, given VRF reveal. Useful for
    /// committee members with nothing to observe in a given slot.
    #[must_use]
    pub const fn vrf_only(vrf_output: VrfOutput, vrf_proof: VrfProof) -> Self {
        Self {
            witnesses: BoundedVec::new(),
            vrf_output,
            vrf_proof,
        }
    }

    /// Observations the proposer is submitting this slot.
    #[must_use]
    pub const fn witnesses(&self) -> &BoundedVec<Witness, MAX_WITNESSES_PER_PROPOSER> {
        &self.witnesses
    }

    /// VRF output for this slot — mixed into beacon randomness once
    /// the committee commits to the slot's proposal set.
    #[must_use]
    pub const fn vrf_output(&self) -> VrfOutput {
        self.vrf_output
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

    fn sample_witness(leaf_index: u64) -> Witness {
        Witness::Shard(ShardWitness {
            payload: ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(1),
                amount: Stake::from_whole_tokens(1_000),
            },
            proof: ShardWitnessProof {
                shard_id: ShardGroupId::new(0),
                committed_block_hash: BlockHash::ZERO,
                leaf_index: LeafIndex::new(leaf_index),
                siblings: Vec::new().into(),
            },
        })
    }

    fn sample_proposal() -> BeaconProposal {
        BeaconProposal::new(
            vec![sample_witness(0), sample_witness(1), sample_witness(2)],
            VrfOutput([0xAB; 32]),
            VrfProof([0xCD; 96]),
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
        let p = BeaconProposal::vrf_only(VrfOutput::ZERO, VrfProof::ZERO);
        assert!(p.witnesses().is_empty());
        assert_eq!(p.vrf_output(), VrfOutput::ZERO);
        assert_eq!(p.vrf_proof(), VrfProof::ZERO);
    }

    /// Hand-roll a `BeaconProposal` whose `witnesses` length prefix
    /// exceeds the cap. The `BoundedVec` decoder fires before any
    /// per-element work happens.
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
            // Oversized witnesses array.
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(Witness::value_kind()).unwrap();
            enc.write_size(MAX_WITNESSES_PER_PROPOSER + 1).unwrap();
            // Don't bother writing the rest — decode fails on the count.
            let _ = &proposal;
        }
        let err = basic_decode::<BeaconProposal>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_WITNESSES_PER_PROPOSER
                    && actual == MAX_WITNESSES_PER_PROPOSER + 1
        ));
    }

    #[test]
    fn accessors_return_built_values() {
        let p = sample_proposal();
        assert_eq!(p.witnesses().len(), 3);
        assert_eq!(p.vrf_output(), VrfOutput([0xAB; 32]));
        assert_eq!(p.vrf_proof(), VrfProof([0xCD; 96]));
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
