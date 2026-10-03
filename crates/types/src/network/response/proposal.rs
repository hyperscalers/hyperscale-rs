//! Proposal fetch response.

use hyperscale_hbor::Hbor;

use crate::network::notification::BlockHeaderNotification;
use crate::{MessageClass, NetworkMessage};

/// Response to a
/// [`GetProposalRequest`](crate::network::request::GetProposalRequest).
///
/// Carries the proposal as its proposer broadcast it, signature and all,
/// if the responder held it; otherwise `None`, which the requester reads
/// as "this peer doesn't have it; try another."
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetProposalResponse {
    /// The proposal, if the responder held it.
    pub proposal: Option<BlockHeaderNotification>,
}

impl GetProposalResponse {
    /// Build a response from an optional proposal.
    #[must_use]
    pub const fn new(proposal: Option<BlockHeaderNotification>) -> Self {
        Self { proposal }
    }

    /// Empty response — the responder didn't hold the proposal.
    #[must_use]
    pub const fn empty() -> Self {
        Self { proposal: None }
    }
}

impl NetworkMessage for GetProposalResponse {
    fn message_type_id() -> &'static str {
        "block.proposal.response"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}
