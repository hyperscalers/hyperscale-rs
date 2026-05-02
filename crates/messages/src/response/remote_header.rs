//! Range response for remote committed block headers.

use hyperscale_types::{CommittedBlockHeader, MessageClass, NetworkMessage};
use sbor::prelude::BasicSbor;

/// Response to a [`crate::request::GetRemoteHeadersRequest`].
///
/// Carries up to `count` consecutive headers starting at the requested
/// `from_height`, in ascending height order. Empty when the responder
/// has no header at `from_height`; otherwise contiguous from
/// `from_height` up to whatever the responder could serve before
/// hitting either `count`, [`crate::request::MAX_REMOTE_HEADERS_PER_REQUEST`],
/// or its own tip.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetRemoteHeadersResponse {
    /// Consecutive committed headers in ascending height order.
    pub headers: Vec<CommittedBlockHeader>,
}

impl NetworkMessage for GetRemoteHeadersResponse {
    fn message_type_id() -> &'static str {
        "remote_header.response"
    }

    fn class() -> MessageClass {
        MessageClass::Recovery
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbor_roundtrip_empty() {
        let response = GetRemoteHeadersResponse { headers: vec![] };

        let encoded = sbor::basic_encode(&response).unwrap();
        let decoded: GetRemoteHeadersResponse = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
