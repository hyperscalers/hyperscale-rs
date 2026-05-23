//! Multi-Slot Consensus (MSC) wire types.
//!
//! MSC composes per-slot [`SPC`](super::spc) instances into the
//! beacon's slot pipeline. Two wire types ride between participants:
//!
//! - [`MscSlotProposal`] — a committee member's payload for a slot.
//!   The opaque `content` is encoded by the beacon application
//!   (currently a serialized [`BeaconProposal`](crate::BeaconProposal))
//!   into a [`PcVector`], the form PC operates on inside the slot.
//! - [`MscEmptyLowAccusation`] — the slot-tagged form of
//!   [`SpcEmptyLowEvidence`](super::spc::SpcEmptyLowEvidence); a
//!   participant attaches these to their next slot's proposal so MSC
//!   can demote validators whose slot produced an empty low.

use sbor::prelude::*;

use crate::{PcQc3, PcVector, Slot, SpcView};

/// What one committee member proposes to MSC for a slot — opaque
/// payload + the slot it belongs to.
///
/// The beacon application packs an encoded
/// [`BeaconProposal`](crate::BeaconProposal) into `content`. MSC and
/// PC underneath treat `content` as opaque [`PcValueElement`s] for
/// their max-common-prefix arithmetic.
///
/// [`PcValueElement`s]: crate::PcValueElement
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct MscSlotProposal {
    /// Slot this proposal targets.
    pub slot: Slot,
    /// Application-encoded payload; opaque to MSC and PC.
    pub content: PcVector,
}

/// Slot-tagged accusation that some SPC view in `slot` produced an
/// empty-low output.
///
/// Participants record these locally as their inner SPC produces
/// empty lows from views > 1, then attach them to the next slot's
/// outgoing proposal so MSC's ranking update can demote the accused
/// validators.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct MscEmptyLowAccusation {
    /// Slot whose SPC instance produced this empty-low output.
    pub slot: Slot,
    /// SPC view inside that slot. Must be `> 1` (view 1 is excused).
    pub view: SpcView,
    /// Round-3 cert from `view`'s inner PC. `proof.x_pp().is_empty()`
    /// is the empty-low witness.
    pub proof: PcQc3,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Bls12381G2Signature, PcQc2, PcValueElement, PcXpProof, SignerBitfield};

    fn sample_pc_qc3() -> PcQc3 {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        let qc2 = PcQc2::new(
            PcVector::empty(),
            signers,
            Bls12381G2Signature([0x11; 96]),
            PcXpProof::Full {
                length_multi_sig: Bls12381G2Signature([0x22; 96]),
            },
        );
        PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            Vec::new(),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    fn sample_pc_vector(len: u8) -> PcVector {
        PcVector::new((0..len).map(|n| PcValueElement::new([n; 32])))
    }

    #[test]
    fn slot_proposal_sbor_round_trip() {
        let p = MscSlotProposal {
            slot: Slot::new(42),
            content: sample_pc_vector(3),
        };
        let bytes = basic_encode(&p).unwrap();
        let decoded: MscSlotProposal = basic_decode(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn empty_low_accusation_sbor_round_trip() {
        let a = MscEmptyLowAccusation {
            slot: Slot::new(42),
            view: SpcView::new(3),
            proof: sample_pc_qc3(),
        };
        let bytes = basic_encode(&a).unwrap();
        let decoded: MscEmptyLowAccusation = basic_decode(&bytes).unwrap();
        assert_eq!(a, decoded);
    }
}
