//! Proposal fetch — pull a block proposal a committee member voted for
//! from a peer that holds it.
//!
//! A proposal header goes out once, to the committee, and nothing else
//! carries it until a quorum certifies it. A member it missed cannot vote
//! on it, and in a committee that needs every vote that loses the round.
//! A vote names the block it is for, so a member holding a vote for a
//! block it never received asks for that block by hash.

use hyperscale_hbor::Hbor;

use crate::network::response::GetProposalResponse;
use crate::{BlockHash, MessageClass, NetworkMessage, Request};

/// Fetch the proposal whose block hash is `block_hash`.
///
/// Served from the proposals the responder has admitted, signed by their
/// proposer, otherwise an empty response. The requester admits the
/// answer through the same checks as a gossiped header.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetProposalRequest {
    /// Hash of the proposed block — the value the vote named.
    pub block_hash: BlockHash,
}

impl GetProposalRequest {
    /// Build a request for `block_hash`.
    #[must_use]
    pub const fn new(block_hash: BlockHash) -> Self {
        Self { block_hash }
    }
}

impl NetworkMessage for GetProposalRequest {
    fn message_type_id() -> &'static str {
        "block.proposal.request"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl Request for GetProposalRequest {
    type Response = GetProposalResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.proposal.is_none()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::Hash;

    #[test]
    fn hbor_round_trip() {
        let req = GetProposalRequest::new(BlockHash::from_raw(Hash::from_bytes(b"proposal")));
        let bytes = hbor_to_vec(&req).unwrap();
        let decoded: GetProposalRequest = hbor_from_slice(&bytes).unwrap();
        assert_eq!(req, decoded);
    }
}
