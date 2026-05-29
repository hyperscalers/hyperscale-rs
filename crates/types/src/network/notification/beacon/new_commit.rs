//! SPC new-commit notification — announces a committed-high triple.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{MessageClass, NetworkMessage, SpcNewCommitMsg, Verifiable};

/// Committed-low announcement broadcast within the slot's committee
/// when an SPC participant commits a verifiable low value.
///
/// The inner [`SpcNewCommitMsg`] is self-authenticating via its
/// embedded `PcQc3` — verifiers check the committee aggregate in the
/// proof and that `proof.x_pp() == value`. The notification carries
/// no outer signature; sender identity is not load-bearing for
/// verification. Wire decode lands the wrapper as
/// `Verifiable::Unverified`; locally-dispatched sends preserve the
/// `Verified` marker.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SpcNewCommitNotification {
    /// The committed new-commit message.
    pub msg: Arc<Verifiable<SpcNewCommitMsg>>,
}

impl SpcNewCommitNotification {
    /// Wrap an [`SpcNewCommitMsg`] for notification. Accepts a raw
    /// message or a `Verified<SpcNewCommitMsg>` — the wrapper preserves
    /// the marker.
    #[must_use]
    pub fn new(msg: impl Into<Arc<Verifiable<SpcNewCommitMsg>>>) -> Self {
        Self { msg: msg.into() }
    }

    /// Get the inner message (raw view, regardless of verification
    /// state).
    #[must_use]
    pub fn msg(&self) -> &SpcNewCommitMsg {
        self.msg.as_unverified()
    }

    /// Consume and return the inner message, preserving the
    /// verification marker.
    #[must_use]
    pub fn into_msg(self) -> Arc<Verifiable<SpcNewCommitMsg>> {
        self.msg
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

    fn sample_msg() -> SpcNewCommitMsg {
        SpcNewCommitMsg {
            view: SpcView::new(4),
            value: PcVector::empty(),
            proof: sample_pc_qc3().into(),
        }
    }

    #[test]
    fn sbor_round_trip() {
        let n = SpcNewCommitNotification::new(Arc::new(Verifiable::from(sample_msg())));
        let bytes = basic_encode(&n).unwrap();
        let decoded: SpcNewCommitNotification = basic_decode(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(SpcNewCommitNotification::class(), MessageClass::Consensus);
    }
}
