//! Candidate beacon-block gossip — the SPC output awaiting
//! ratification.

use std::sync::Arc;

use hyperscale_hbor::Hbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{CandidateBeaconBlock, MessageClass, NetworkMessage, Verifiable};

/// Broadcasts an SPC-certified [`CandidateBeaconBlock`] to the active
/// validator pool for ratification.
///
/// The candidate is self-authenticating via its SPC proposal
/// certificate — verifiers check it under the epoch's committee. It
/// confers no commit authority: pool members that verify it prevote
/// its hash, and only a
/// [`RatifyCert`](crate::RatifyCert) commits the block. Multiple
/// publishers broadcasting the same canonical bytes collapse via
/// gossipsub's bytes-id dedup.
///
/// Wire decode lands the wrapper as `Verifiable::Unverified`;
/// locally-dispatched sends from a colocated SPC commit path preserve
/// `Verifiable::Verified`.
///
/// `MessageClass::Consensus` — the candidate is ratification's input:
/// until it reaches the pool, only the skip hash is prevotable.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct BeaconCandidateGossip {
    /// The candidate block paired with its SPC proposal certificate.
    pub candidate: Arc<Verifiable<CandidateBeaconBlock>>,
}

impl BeaconCandidateGossip {
    /// Wrap a [`CandidateBeaconBlock`] for gossip broadcast. Accepts a
    /// raw candidate or a `Verified<CandidateBeaconBlock>` — the
    /// wrapper preserves the marker.
    #[must_use]
    pub fn new(candidate: impl Into<Arc<Verifiable<CandidateBeaconBlock>>>) -> Self {
        Self {
            candidate: candidate.into(),
        }
    }

    /// Get the inner candidate (raw view, regardless of verification
    /// state).
    #[must_use]
    pub fn candidate(&self) -> &CandidateBeaconBlock {
        self.candidate.as_unverified()
    }

    /// Consume and return the inner candidate, preserving the
    /// verification marker.
    #[must_use]
    pub fn into_candidate(self) -> Arc<Verifiable<CandidateBeaconBlock>> {
        self.candidate
    }
}

impl NetworkMessage for BeaconCandidateGossip {
    fn message_type_id() -> &'static str {
        "beacon.candidate"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl GossipMessage for BeaconCandidateGossip {
    const SCOPE: TopicScope = TopicScope::Global;
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Capped, from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{
        AggregateSignature, BeaconBlock, BeaconBlockHash, Epoch, Hash, PcQc2, PcQc3,
        PcSignerLengths, PcVector, PcXpProof, SignerBitfield, SpcCert, SpcView,
    };

    fn sample_candidate() -> CandidateBeaconBlock {
        let qc2 = PcQc2::new(
            PcVector::empty(),
            SignerBitfield::new(4),
            AggregateSignature::new([0x11; 96]),
            PcXpProof::Full,
        );
        let qc3 = PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            SignerBitfield::new(4),
            PcSignerLengths::Uniform(0),
            AggregateSignature::new([0x11; 96]),
        );
        CandidateBeaconBlock::new(
            BeaconBlock::new(
                Epoch::new(3),
                BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
                Capped::empty(),
            ),
            Box::new(SpcCert::Direct {
                prev_view: SpcView::INITIAL,
                value: PcVector::empty(),
                proof: qc3.into(),
            }),
        )
    }

    #[test]
    fn hbor_round_trip() {
        let g = BeaconCandidateGossip::new(Arc::new(Verifiable::from(sample_candidate())));
        let bytes = hbor_to_vec(&g).unwrap();
        let decoded: BeaconCandidateGossip = hbor_from_slice(&bytes).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(BeaconCandidateGossip::class(), MessageClass::Consensus);
    }

    #[test]
    fn scope_is_global() {
        assert!(matches!(BeaconCandidateGossip::SCOPE, TopicScope::Global));
    }
}
