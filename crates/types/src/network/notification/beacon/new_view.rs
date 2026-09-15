//! SPC new-view notification — the view leader's view-entry authorization.

use std::sync::Arc;

use hyperscale_hbor::Hbor;

use crate::{
    ConsensusSignature, Epoch, MessageClass, NetworkDefinition, NetworkMessage, Signed,
    SpcProposalObject, SpcRelayKind, SpcRelayMessage, ValidatorId, Verifiable, signed_bytes,
};

/// View-entry authorization sent by a beacon-committee member to the
/// rest of the committee.
///
/// The inner [`SpcProposalObject`] carries the view this proposal
/// authorizes entry to and the certificate backing the authorization
/// (either the previous view's verifiable output, or an indirect cert
/// built from `f+1` empty-view attestations). The cert is
/// self-authenticating — verifiers check the embedded `PcQc3` (Direct)
/// or `f+1` skip-sig set (Indirect) — so the inner payload doesn't
/// need a sender signature for content authentication.
///
/// `sender` + `sender_signature` ride on the wrapper for relay
/// accountability: the signature is a signature under the sender's key
/// over `(network, epoch, view, proposal.hash())`. The receiver uses
/// the verified sender to key per-`(epoch, view, sender)` pipeline
/// slots; peer-scoring + topology committee-membership gates ride on
/// the same attribution.
///
/// Wire decode lands the inner wrapper as `Verifiable::Unverified`;
/// locally-dispatched sends preserve the `Verified` marker.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct SpcNewViewNotification {
    /// Epoch the inner SPC instance belongs to. Bound into the
    /// signing message so a swap across epochs invalidates the sig.
    pub(crate) epoch: Epoch,
    /// Validator relaying this proposal — the implicit signer of
    /// `sender_signature`.
    pub sender: ValidatorId,
    /// Signature over the [`SpcRelayMessage`] for
    /// `(epoch, proposal.view, proposal.hash())`.
    pub(crate) sender_signature: ConsensusSignature,
    /// The proposal object.
    pub proposal: Arc<Verifiable<SpcProposalObject>>,
}

impl SpcNewViewNotification {
    /// Wrap an [`SpcProposalObject`] for notification with the
    /// relay-attestation sender + signature. The caller produces
    /// `sender_signature` over the [`SpcRelayMessage`].
    #[must_use]
    pub fn new(
        epoch: Epoch,
        sender: ValidatorId,
        sender_signature: ConsensusSignature,
        proposal: impl Into<Arc<Verifiable<SpcProposalObject>>>,
    ) -> Self {
        Self {
            epoch,
            sender,
            sender_signature,
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

impl Signed for SpcNewViewNotification {
    fn signer(&self) -> ValidatorId {
        self.sender
    }

    fn signature(&self) -> &ConsensusSignature {
        &self.sender_signature
    }

    fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        signed_bytes(
            &SpcRelayMessage {
                kind: SpcRelayKind::NewView,
                epoch: self.epoch,
                view: self.proposal.as_unverified().view,
                content_hash: self.proposal.as_unverified().hash(),
            },
            network,
        )
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
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{
        AggregateSignature, Epoch, PcQc2, PcQc3, PcSignerLengths, PcVector, PcXpProof,
        SignerBitfield, SpcCert, SpcView, ValidatorId,
    };

    fn sample_pc_qc3() -> PcQc3 {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        let qc2 = PcQc2::new(
            PcVector::empty(),
            signers,
            AggregateSignature::new([0x11; 96]),
            PcXpProof::Full,
        );
        PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            SignerBitfield::new(4),
            PcSignerLengths::Uniform(0),
            AggregateSignature::new([0x33; 96]),
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
    fn hbor_round_trip() {
        let n = SpcNewViewNotification::new(
            Epoch::new(7),
            ValidatorId::new(3),
            ConsensusSignature::new([0x44; 96]),
            Arc::new(Verifiable::from(sample_proposal())),
        );
        let bytes = hbor_to_vec(&n).unwrap();
        let decoded: SpcNewViewNotification = hbor_from_slice(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(SpcNewViewNotification::class(), MessageClass::Consensus);
    }
}
