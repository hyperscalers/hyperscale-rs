//! Single-proposal fetch response.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{BeaconProposal, MessageClass, NetworkMessage, Verifiable};

/// Response to a
/// [`GetBeaconProposalRequest`](crate::network::request::beacon::GetBeaconProposalRequest).
///
/// Carries the responder's pooled proposal if held, otherwise `None`
/// — the requester treats `None` as "this peer doesn't have it; try
/// another." Wire decode lands the wrapper as
/// [`Verifiable::Unverified`]; locally-dispatched serves preserve the
/// `Verified` marker.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBeaconProposalResponse {
    /// The proposal, if the responder had it pooled.
    pub proposal: Option<Arc<Verifiable<BeaconProposal>>>,
}

impl GetBeaconProposalResponse {
    /// Build a response from an optional proposal.
    #[must_use]
    pub const fn new(proposal: Option<Arc<Verifiable<BeaconProposal>>>) -> Self {
        Self { proposal }
    }

    /// Empty response — responder didn't have the proposal.
    #[must_use]
    pub const fn empty() -> Self {
        Self { proposal: None }
    }
}

impl NetworkMessage for GetBeaconProposalResponse {
    fn message_type_id() -> &'static str {
        "beacon.proposal.response"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::{VrfOutput, VrfProof};

    fn sample_proposal() -> Arc<Verifiable<BeaconProposal>> {
        Arc::new(Verifiable::from(BeaconProposal::vrf_only(
            VrfOutput::new([0xAB; 32]),
            VrfProof::new([0xCD; 96]),
        )))
    }

    #[test]
    fn sbor_round_trip_some() {
        let resp = GetBeaconProposalResponse::new(Some(sample_proposal()));
        let bytes = basic_encode(&resp).unwrap();
        let decoded: GetBeaconProposalResponse = basic_decode(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn sbor_round_trip_empty() {
        let resp = GetBeaconProposalResponse::empty();
        let bytes = basic_encode(&resp).unwrap();
        let decoded: GetBeaconProposalResponse = basic_decode(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(GetBeaconProposalResponse::class(), MessageClass::Consensus);
    }
}
