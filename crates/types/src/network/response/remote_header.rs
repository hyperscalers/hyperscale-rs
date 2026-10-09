//! Range response for remote committed block headers.

use hyperscale_hbor::{Capped, Hbor};

use crate::network::request::MAX_REMOTE_HEADERS_PER_REQUEST;
use crate::{BlockHeight, CertifiedBlockHeader, MessageClass, NetworkMessage};

/// [`MAX_REMOTE_HEADERS_PER_REQUEST`] as a length, for the decode cap.
///
/// The count is a `u64` on the wire and a length here; the assert is
/// what keeps the two spellings from drifting.
const MAX_REMOTE_HEADERS_PER_REQUEST_LEN: usize = 64;

const _: () = assert!(
    MAX_REMOTE_HEADERS_PER_REQUEST_LEN as u64 == MAX_REMOTE_HEADERS_PER_REQUEST.inner(),
    "the decode cap is the request's own ceiling",
);

/// Response to a [`crate::network::request::GetRemoteHeadersRequest`].
///
/// Carries up to `count` consecutive headers starting at the requested
/// `from_height`, in ascending height order. Empty when the responder
/// has no header at `from_height`; otherwise contiguous from
/// `from_height` up to whatever the responder could serve before
/// hitting either `count`, [`crate::network::request::MAX_REMOTE_HEADERS_PER_REQUEST`],
/// or its own tip.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetRemoteHeadersResponse {
    /// Consecutive certified headers in ascending height order.
    ///
    /// Capped at what one request may ask for, which is the most a
    /// responder can honestly have been asked to serve.
    pub headers: Capped<Vec<CertifiedBlockHeader>, MAX_REMOTE_HEADERS_PER_REQUEST_LEN>,
    /// The responder's chain floor, set when `from_height` lies beneath
    /// it: the responder holds no header there and will not again, so a
    /// requester whose frontier sits below it cannot sync forward from
    /// there.
    pub floor: Option<BlockHeight>,
}

impl GetRemoteHeadersResponse {
    /// A response carrying `headers`.
    #[must_use]
    pub const fn of(
        headers: Capped<Vec<CertifiedBlockHeader>, MAX_REMOTE_HEADERS_PER_REQUEST_LEN>,
    ) -> Self {
        Self {
            headers,
            floor: None,
        }
    }

    /// A response carrying no header.
    #[must_use]
    pub const fn empty() -> Self {
        Self::of(Capped::empty())
    }

    /// A response for a `from_height` beneath the responder's `floor`.
    #[must_use]
    pub const fn below_floor(floor: BlockHeight) -> Self {
        Self {
            headers: Capped::empty(),
            floor: Some(floor),
        }
    }
}

impl NetworkMessage for GetRemoteHeadersResponse {
    fn message_type_id() -> &'static str {
        "remote_header.response"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    #[test]
    fn test_hbor_roundtrip_empty() {
        let response = GetRemoteHeadersResponse::empty();

        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetRemoteHeadersResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
