//! Prefix Consensus round-2 vote notification.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{MessageClass, NetworkMessage, PcVote2};

/// PC round-2 vote sent via unicast to peers in the slot's committee.
///
/// The inner [`PcVote2`] is self-authenticating — it carries the signer
/// id, one BLS signature per prefix of `x`, the round-1 QC the signer
/// is building on, and a length attestation pinning `|x|`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcVote2Notification {
    /// The vote.
    pub vote: Arc<PcVote2>,
}

impl PcVote2Notification {
    /// Wrap a [`PcVote2`] for notification.
    #[must_use]
    pub fn new(vote: impl Into<Arc<PcVote2>>) -> Self {
        Self { vote: vote.into() }
    }

    /// Get the inner vote.
    #[must_use]
    pub fn vote(&self) -> &PcVote2 {
        &self.vote
    }

    /// Consume and return the inner vote.
    #[must_use]
    pub fn into_vote(self) -> Arc<PcVote2> {
        self.vote
    }
}

impl NetworkMessage for PcVote2Notification {
    fn message_type_id() -> &'static str {
        "beacon.pc.vote2"
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
        Bls12381G2Signature, PcCompactVote, PcQc1, PcVector, PositionalBundle, SignerBitfield,
        ValidatorId,
    };

    fn sample_qc1() -> PcQc1 {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        PcQc1::new(
            PcVector::empty(),
            PositionalBundle::new(signers, vec![PcCompactVote::new(0, None)]),
            Bls12381G2Signature([0xAA; 96]),
        )
    }

    fn sample_vote() -> PcVote2 {
        PcVote2::new(
            ValidatorId::new(2),
            PcVector::empty(),
            vec![Bls12381G2Signature([0x11; 96])],
            sample_qc1(),
            Bls12381G2Signature([0x22; 96]),
        )
    }

    #[test]
    fn sbor_round_trip() {
        let n = PcVote2Notification::new(sample_vote());
        let bytes = basic_encode(&n).unwrap();
        let decoded: PcVote2Notification = basic_decode(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(PcVote2Notification::class(), MessageClass::Consensus);
    }
}
