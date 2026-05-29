//! Prefix Consensus round-1 vote notification.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{MessageClass, NetworkMessage, PcVote1, Verifiable};

/// PC round-1 vote sent via unicast to peers in the slot's committee.
///
/// The inner [`PcVote1`] is self-authenticating — it carries the signer
/// id and one BLS signature per prefix of `v_in`. Wire decode lands the
/// wrapper as `Verifiable::Unverified`; local-dispatched sends from a
/// colocated voter preserve `Verifiable::Verified`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcVote1Notification {
    /// The vote.
    pub vote: Arc<Verifiable<PcVote1>>,
}

impl PcVote1Notification {
    /// Wrap a [`PcVote1`] for notification. Accepts a raw vote or a
    /// `Verified<PcVote1>` — the wrapper preserves the marker.
    #[must_use]
    pub fn new(vote: impl Into<Arc<Verifiable<PcVote1>>>) -> Self {
        Self { vote: vote.into() }
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
    use sbor::prelude::*;

    use super::*;
    use crate::{Bls12381G2Signature, PcVector, ValidatorId};

    fn sample_vote() -> PcVote1 {
        PcVote1::new(
            ValidatorId::new(2),
            PcVector::empty(),
            vec![Bls12381G2Signature([0x11; 96])],
        )
    }

    #[test]
    fn sbor_round_trip() {
        let n = PcVote1Notification::new(Arc::new(Verifiable::from(sample_vote())));
        let bytes = basic_encode(&n).unwrap();
        let decoded: PcVote1Notification = basic_decode(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(PcVote1Notification::class(), MessageClass::Consensus);
    }
}
