//! Range response for remote committed block headers.

use hyperscale_hbor::{Capped, Hbor};

use crate::network::request::MAX_REMOTE_HEADERS_PER_REQUEST;
use crate::{CertifiedBlockHeader, MessageClass, NetworkMessage};

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
        let response = GetRemoteHeadersResponse {
            headers: Capped::empty(),
        };

        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetRemoteHeadersResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
