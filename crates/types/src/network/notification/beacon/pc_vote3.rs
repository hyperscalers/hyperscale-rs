//! Prefix Consensus round-3 vote notification.

use std::sync::Arc;

use hyperscale_hbor::Hbor;

use crate::{Epoch, MessageClass, NetworkMessage, PcVote3, SpcView, Verifiable};

/// PC round-3 vote sent via unicast to peers in the slot's committee.
///
/// The inner [`PcVote3`] is self-authenticating — it carries the signer
/// id, an individual sig over the certified mcp `x_p`, and the round-2
/// QC anchoring `x_p`. The wrapping `epoch` and `view` ride alongside
/// because PC votes don't carry their scope internally. Wire decode lands the
/// wrapper as `Verifiable::Unverified`; local-dispatched sends from a
/// colocated voter preserve `Verifiable::Verified`.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct PcVote3Notification {
    /// Epoch whose SPC instance produced this vote. Bound into the
    /// vote's signing scope, so a vote relabelled across epochs fails
    /// verification.
    pub epoch: Epoch,
    /// SPC view whose inner PC produced this vote.
    pub view: SpcView,
    /// The vote.
    pub vote: Arc<Verifiable<PcVote3>>,
}

impl PcVote3Notification {
    /// Wrap a [`PcVote3`] for notification. Accepts a raw vote or a
    /// `Verified<PcVote3>`.
    #[must_use]
    pub fn new(epoch: Epoch, view: SpcView, vote: impl Into<Arc<Verifiable<PcVote3>>>) -> Self {
        Self {
            epoch,
            view,
            vote: vote.into(),
        }
    }

    /// Get the inner vote (raw view, regardless of verification state).
    #[must_use]
    pub fn vote(&self) -> &PcVote3 {
        self.vote.as_unverified()
    }

    /// Consume and return the inner vote, preserving the verification
    /// marker.
    #[must_use]
    pub fn into_vote(self) -> Arc<Verifiable<PcVote3>> {
        self.vote
    }
}

impl NetworkMessage for PcVote3Notification {
    fn message_type_id() -> &'static str {
        "beacon.pc.vote3"
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
        AggregateSignature, ConsensusSignature, PcQc2, PcVector, PcXpProof, SignerBitfield,
        SpcView, ValidatorId,
    };

    fn sample_qc2() -> PcQc2 {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        PcQc2::new(
            PcVector::empty(),
            signers,
            AggregateSignature::new([0x11; 96]),
            PcXpProof::Full,
        )
    }

    fn sample_vote() -> PcVote3 {
        PcVote3::new(
            ValidatorId::new(2),
            PcVector::empty(),
            ConsensusSignature::new([0x33; 96]),
            sample_qc2(),
        )
    }

    #[test]
    fn hbor_round_trip() {
        let n = PcVote3Notification::new(
            Epoch::new(3),
            SpcView::new(2),
            Arc::new(Verifiable::from(sample_vote())),
        );
        let bytes = hbor_to_vec(&n).unwrap();
        let decoded: PcVote3Notification = hbor_from_slice(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(PcVote3Notification::class(), MessageClass::Consensus);
    }
}
