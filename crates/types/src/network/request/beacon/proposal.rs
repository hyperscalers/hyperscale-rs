//! Single-proposal fetch — pull a committee member's
//! `BeaconProposal` for an in-flight epoch from a peer who has it.
//!
//! Used when SPC's `OutputHigh` references a `(validator, epoch)`
//! whose proposal the local pool never saw — the local node can't
//! assemble the committed block until that proposal arrives. Any
//! beacon-committee member at `epoch` can serve.

use sbor::prelude::BasicSbor;

use crate::network::response::beacon::GetBeaconProposalResponse;
use crate::{Epoch, MessageClass, NetworkMessage, Request, ValidatorId};

/// Fetch one committee member's `BeaconProposal` for an in-flight
/// epoch.
///
/// Served from the responder's `BeaconProposalPool` — returns the
/// pooled `Verified<BeaconProposal>` if the responder admitted it,
/// otherwise an empty response. The requester verifies the signer
/// matches `validator` and the proposal's hash matches the
/// element in SPC's committed `PcVector` before admitting.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBeaconProposalRequest {
    /// Epoch the proposal targets.
    pub epoch: Epoch,
    /// Validator whose proposal is being fetched.
    pub validator: ValidatorId,
}

impl GetBeaconProposalRequest {
    /// Build a request from its parts.
    #[must_use]
    pub const fn new(epoch: Epoch, validator: ValidatorId) -> Self {
        Self { epoch, validator }
    }
}

impl NetworkMessage for GetBeaconProposalRequest {
    fn message_type_id() -> &'static str {
        "beacon.proposal.request"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl Request for GetBeaconProposalRequest {
    type Response = GetBeaconProposalResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.proposal.is_none()
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;

    #[test]
    fn sbor_round_trip() {
        let req = GetBeaconProposalRequest::new(Epoch::new(42), ValidatorId::new(7));
        let bytes = basic_encode(&req).unwrap();
        let decoded: GetBeaconProposalRequest = basic_decode(&bytes).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(GetBeaconProposalRequest::class(), MessageClass::Consensus);
    }
}
