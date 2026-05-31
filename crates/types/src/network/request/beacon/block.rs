//! Beacon block gap-fill sync request — pull the committed
//! `CertifiedBeaconBlock` at an epoch from a peer who has it.
//!
//! Catch-up traffic for a coordinator behind the live tip: reach
//! matters, latency doesn't. Any peer that committed the epoch can
//! serve it from beacon storage.

use sbor::prelude::BasicSbor;

use crate::network::response::beacon::GetBeaconBlockResponse;
use crate::{Epoch, MessageClass, NetworkMessage, Request};

/// Fetch the committed `CertifiedBeaconBlock` at `epoch`.
///
/// Served from the responder's beacon storage by epoch — an empty
/// response means "this peer doesn't have it; try another." The
/// requester verifies the block's cert before applying.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBeaconBlockRequest {
    /// Epoch whose committed beacon block is being fetched.
    pub epoch: Epoch,
}

impl GetBeaconBlockRequest {
    /// Build a request for `epoch`.
    #[must_use]
    pub const fn new(epoch: Epoch) -> Self {
        Self { epoch }
    }
}

impl NetworkMessage for GetBeaconBlockRequest {
    fn message_type_id() -> &'static str {
        "beacon.block.request"
    }

    fn class() -> MessageClass {
        MessageClass::Recovery
    }
}

impl Request for GetBeaconBlockRequest {
    type Response = GetBeaconBlockResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.block.is_none()
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;

    #[test]
    fn sbor_round_trip() {
        let req = GetBeaconBlockRequest::new(Epoch::new(42));
        let bytes = basic_encode(&req).unwrap();
        let decoded: GetBeaconBlockRequest = basic_decode(&bytes).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn class_is_recovery() {
        assert_eq!(GetBeaconBlockRequest::class(), MessageClass::Recovery);
    }
}
