//! SPC empty-view notification.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{MessageClass, NetworkMessage, SpcEmptyViewMsg, Verifiable};

/// SPC empty-view declaration sent via unicast when a participant
/// times out on a view without observing a leader proposal.
///
/// The inner [`SpcEmptyViewMsg`] is self-authenticating — it carries
/// the signer id and a BLS signature over the canonical empty-view
/// signing bytes. Wire decode lands the wrapper as
/// `Verifiable::Unverified`; locally-dispatched sends from a
/// colocated signer preserve `Verifiable::Verified`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SpcEmptyViewMsgNotification {
    /// The empty-view message.
    pub msg: Arc<Verifiable<SpcEmptyViewMsg>>,
}

impl SpcEmptyViewMsgNotification {
    /// Wrap an [`SpcEmptyViewMsg`] for notification. Accepts a raw msg
    /// or a `Verified<SpcEmptyViewMsg>` — the wrapper preserves the
    /// marker.
    #[must_use]
    pub fn new(msg: impl Into<Arc<Verifiable<SpcEmptyViewMsg>>>) -> Self {
        Self { msg: msg.into() }
    }

    /// Get the inner empty-view message (raw view, regardless of
    /// verification state).
    #[must_use]
    pub fn msg(&self) -> &SpcEmptyViewMsg {
        self.msg.as_unverified()
    }

    /// Consume and return the inner empty-view message, preserving the
    /// verification marker.
    #[must_use]
    pub fn into_msg(self) -> Arc<Verifiable<SpcEmptyViewMsg>> {
        self.msg
    }
}

impl NetworkMessage for SpcEmptyViewMsgNotification {
    fn message_type_id() -> &'static str {
        "beacon.spc.empty_view"
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
        SpcHighTriple, SpcView, ValidatorId,
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

    fn sample_msg() -> SpcEmptyViewMsg {
        SpcEmptyViewMsg {
            view: SpcView::new(5),
            reported: SpcHighTriple {
                view: SpcView::new(3),
                value: PcVector::empty(),
                proof: sample_pc_qc3().into(),
            },
            signer: ValidatorId::new(2),
            sig: Bls12381G2Signature([0x44; 96]),
        }
    }

    #[test]
    fn sbor_round_trip() {
        let n = SpcEmptyViewMsgNotification::new(Arc::new(Verifiable::from(sample_msg())));
        let bytes = basic_encode(&n).unwrap();
        let decoded: SpcEmptyViewMsgNotification = basic_decode(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(
            SpcEmptyViewMsgNotification::class(),
            MessageClass::Consensus
        );
    }
}
