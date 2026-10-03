//! Candidate fetch response.

use std::sync::Arc;

use hyperscale_hbor::Hbor;

use crate::{CandidateBeaconBlock, MessageClass, NetworkMessage, Verifiable};

/// Response to a
/// [`GetBeaconCandidateRequest`](crate::network::request::beacon::GetBeaconCandidateRequest).
///
/// Carries the responder's candidate if held, otherwise `None` — the
/// requester treats `None` as "this peer doesn't have it; try another."
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetBeaconCandidateResponse {
    /// The candidate, if the responder held it.
    pub candidate: Option<Arc<Verifiable<CandidateBeaconBlock>>>,
}

impl GetBeaconCandidateResponse {
    /// Build a response from an optional candidate.
    #[must_use]
    pub const fn new(candidate: Option<Arc<Verifiable<CandidateBeaconBlock>>>) -> Self {
        Self { candidate }
    }

    /// Empty response — the responder didn't hold the candidate.
    #[must_use]
    pub const fn empty() -> Self {
        Self { candidate: None }
    }
}

impl NetworkMessage for GetBeaconCandidateResponse {
    fn message_type_id() -> &'static str {
        "beacon.candidate.response"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}
