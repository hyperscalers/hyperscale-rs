//! Prefix Consensus round-1 vote notification.

use std::sync::Arc;

use hyperscale_hbor::Hbor;

use crate::{MessageClass, NetworkMessage, PcVote1, SpcView, Verifiable};

/// PC round-1 vote sent via unicast to peers in the slot's committee.
///
/// The inner [`PcVote1`] is self-authenticating — it carries the signer
/// id and one signature per prefix of `v_in`. The wrapping `view`
/// rides alongside because PC votes don't carry their SPC view
/// internally and the receiver needs it to route the vote to the
/// right SPC sub-instance. Wire decode lands the wrapper as
/// `Verifiable::Unverified`; local-dispatched sends from a colocated
/// voter preserve `Verifiable::Verified`.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct PcVote1Notification {
    /// SPC view whose inner PC produced this vote.
    pub view: SpcView,
    /// The vote.
    pub vote: Arc<Verifiable<PcVote1>>,
}

impl PcVote1Notification {
    /// Wrap a [`PcVote1`] for notification. Accepts a raw vote or a
    /// `Verified<PcVote1>` — the wrapper preserves the marker.
    #[must_use]
    pub fn new(view: SpcView, vote: impl Into<Arc<Verifiable<PcVote1>>>) -> Self {
        Self {
            view,
            vote: vote.into(),
        }
    }

    /// Get the inner vote (raw view, regardless of verification state).
    #[must_use]
    pub fn vote(&self) -> &PcVote1 {
        self.vote.as_unverified()
    }

    /// Consume and return the inner vote, preserving the verification
    /// marker.
    #[must_use]
    pub fn into_vote(self) -> Arc<Verifiable<PcVote1>> {
        self.vote
    }
}

impl NetworkMessage for PcVote1Notification {
    fn message_type_id() -> &'static str {
        "beacon.pc.vote1"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Capped, from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{ConsensusSignature, PcVector, ValidatorId};

    fn sample_vote() -> PcVote1 {
        PcVote1::new(
            ValidatorId::new(2),
            PcVector::empty(),
            Capped::from_array([ConsensusSignature::new([0x11; 96])]),
        )
    }

    #[test]
    fn hbor_round_trip() {
        let n =
            PcVote1Notification::new(SpcView::new(2), Arc::new(Verifiable::from(sample_vote())));
        let bytes = hbor_to_vec(&n).unwrap();
        let decoded: PcVote1Notification = hbor_from_slice(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(PcVote1Notification::class(), MessageClass::Consensus);
    }
}
