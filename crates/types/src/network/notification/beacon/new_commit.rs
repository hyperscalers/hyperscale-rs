//! SPC new-commit notification — announces a committed-high triple.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{MessageClass, NetworkMessage, SpcHighTriple};

/// Committed-high announcement broadcast within the slot's committee
/// when an SPC participant commits a verifiable high value.
///
/// The inner [`SpcHighTriple`] is self-authenticating via its embedded
/// `PcQc3` — verifiers check the committee aggregate in the proof.
/// The notification carries no outer signature; sender identity is
/// not load-bearing for verification.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SpcNewCommitNotification {
    /// The committed high triple.
    pub triple: Arc<SpcHighTriple>,
}

impl SpcNewCommitNotification {
    /// Wrap an [`SpcHighTriple`] for notification.
    #[must_use]
    pub fn new(triple: impl Into<Arc<SpcHighTriple>>) -> Self {
        Self {
            triple: triple.into(),
        }
    }

    /// Get the inner triple.
    #[must_use]
    pub fn triple(&self) -> &SpcHighTriple {
        &self.triple
    }

    /// Consume and return the inner triple.
    #[must_use]
    pub fn into_triple(self) -> Arc<SpcHighTriple> {
        self.triple
    }
}

impl NetworkMessage for SpcNewCommitNotification {
    fn message_type_id() -> &'static str {
        "beacon.spc.new_commit"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[cfg(test)]
mod tests {
    use sbor::prelude::*;

    use super::*;
    use crate::{
        Bls12381G2Signature, PcQc2, PcQc3, PcSignerLengths, PcVector, PcXpProof, SignerBitfield,
        SpcView,
    };

    fn sample_pc_qc3() -> PcQc3 {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        let qc2 = PcQc2::new(
            PcVector::empty(),
            signers,
            Bls12381G2Signature([0x11; 96]),
            PcXpProof::Full,
        );
        PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            SignerBitfield::new(4),
            PcSignerLengths::Uniform(0),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    fn sample_triple() -> SpcHighTriple {
        SpcHighTriple {
            view: SpcView::new(4),
            value: PcVector::empty(),
            proof: sample_pc_qc3().into(),
        }
    }

    #[test]
    fn sbor_round_trip() {
        let n = SpcNewCommitNotification::new(sample_triple());
        let bytes = basic_encode(&n).unwrap();
        let decoded: SpcNewCommitNotification = basic_decode(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(SpcNewCommitNotification::class(), MessageClass::Consensus);
    }
}
