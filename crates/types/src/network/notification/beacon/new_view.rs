//! SPC new-view notification — the view leader's view-entry authorization.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{MessageClass, NetworkMessage, SpcProposalObject, Verifiable};

/// View-entry authorization sent by the leader of an SPC view.
///
/// The inner [`SpcProposalObject`] carries the view this proposal
/// authorizes entry to and the certificate backing the authorization
/// (either the previous view's verifiable output, or an indirect cert
/// built from `f+1` empty-view attestations). The cert is
/// self-authenticating — verifiers check the embedded `PcQc3` (Direct)
/// or `f+1` skip-sig set (Indirect) — so the notification carries no
/// outer signature. Wire decode lands the wrapper as
/// `Verifiable::Unverified`; locally-dispatched sends preserve the
/// `Verified` marker.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SpcNewViewNotification {
    /// The proposal object.
    pub proposal: Arc<Verifiable<SpcProposalObject>>,
}

impl SpcNewViewNotification {
    /// Wrap an [`SpcProposalObject`] for notification. Accepts a raw
    /// proposal or a `Verified<SpcProposalObject>` — the wrapper
    /// preserves the marker.
    #[must_use]
    pub fn new(proposal: impl Into<Arc<Verifiable<SpcProposalObject>>>) -> Self {
        Self {
            proposal: proposal.into(),
        }
    }

    /// Get the inner proposal object (raw view, regardless of
    /// verification state).
    #[must_use]
    pub fn proposal(&self) -> &SpcProposalObject {
        self.proposal.as_unverified()
    }

    /// Consume and return the inner proposal object, preserving the
    /// verification marker.
    #[must_use]
    pub fn into_proposal(self) -> Arc<Verifiable<SpcProposalObject>> {
        self.proposal
    }
}

impl NetworkMessage for SpcNewViewNotification {
    fn message_type_id() -> &'static str {
        "beacon.spc.new_view"
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
        SpcCert, SpcView,
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

    fn sample_proposal() -> SpcProposalObject {
        SpcProposalObject {
            view: SpcView::new(2),
            cert: SpcCert::Direct {
                prev_view: SpcView::new(1),
                value: PcVector::empty(),
                proof: sample_pc_qc3().into(),
            },
        }
    }

    #[test]
    fn sbor_round_trip() {
        let n = SpcNewViewNotification::new(Arc::new(Verifiable::from(sample_proposal())));
        let bytes = basic_encode(&n).unwrap();
        let decoded: SpcNewViewNotification = basic_decode(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(SpcNewViewNotification::class(), MessageClass::Consensus);
    }
}
