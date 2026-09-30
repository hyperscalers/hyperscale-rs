//! Candidate fetch — pull the SPC-certified candidate a ratify pool
//! prevoted from a member that holds it.
//!
//! Used when more than the pool's fault bound prevoted a candidate hash
//! the local member never received: without the candidate it can only
//! prevote the skip hash, and a pool split between the two never
//! reaches a quorum. A member that prevoted the hash verified it, so it
//! holds a copy to serve.

use hyperscale_hbor::Hbor;

use crate::network::response::beacon::GetBeaconCandidateResponse;
use crate::{BeaconBlockHash, Epoch, MessageClass, NetworkMessage, Request};

/// Fetch the candidate for `epoch` whose block hash is `block_hash`.
///
/// Served from the responder's candidate cache — the candidates it
/// assembled or verified — otherwise an empty response. The requester
/// admits the answer through the same checks as a gossiped candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetBeaconCandidateRequest {
    /// Epoch the candidate ratifies.
    pub epoch: Epoch,
    /// Hash of the candidate's block — the value the pool prevoted.
    pub block_hash: BeaconBlockHash,
}

impl GetBeaconCandidateRequest {
    /// Build a request from its parts.
    #[must_use]
    pub const fn new(epoch: Epoch, block_hash: BeaconBlockHash) -> Self {
        Self { epoch, block_hash }
    }
}

impl NetworkMessage for GetBeaconCandidateRequest {
    fn message_type_id() -> &'static str {
        "beacon.candidate.request"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl Request for GetBeaconCandidateRequest {
    type Response = GetBeaconCandidateResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.candidate.is_none()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::Hash;

    #[test]
    fn hbor_round_trip() {
        let req = GetBeaconCandidateRequest::new(
            Epoch::new(42),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"candidate")),
        );
        let bytes = hbor_to_vec(&req).unwrap();
        let decoded: GetBeaconCandidateRequest = hbor_from_slice(&bytes).unwrap();
        assert_eq!(req, decoded);
    }
}
