//! Range request for remote committed block headers.
//!
//! Used by the remote-header sync protocol to catch up to a remote shard's
//! tip with one round-trip per batch instead of one per missing height.
//! Any validator in the source shard can serve this from local storage.

use sbor::prelude::BasicSbor;

use crate::network::response::GetRemoteHeadersResponse;
use crate::{BlockHeight, HeaderFetchCount, MessageClass, NetworkMessage, Request, ShardId};

/// Server-enforced upper bound on `count`. Sized to match the block-sync
/// window so the two protocols share batch granularity.
pub const MAX_REMOTE_HEADERS_PER_REQUEST: HeaderFetchCount = HeaderFetchCount::new(64);

/// Request to fetch a contiguous range of committed block headers from a
/// source shard.
///
/// `from_height` is inclusive; the responder returns up to `count` headers
/// starting at `from_height`, capped by [`MAX_REMOTE_HEADERS_PER_REQUEST`]
/// and the responder's local tip. Headers absent from the responder's
/// storage cause the response to short-cap rather than fail.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetRemoteHeadersRequest {
    /// Source shard producing the headers.
    pub source_shard: ShardId,
    /// First height to fetch (inclusive).
    pub from_height: BlockHeight,
    /// Maximum number of consecutive headers to return.
    pub count: HeaderFetchCount,
}

impl NetworkMessage for GetRemoteHeadersRequest {
    fn message_type_id() -> &'static str {
        "remote_header.request"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl Request for GetRemoteHeadersRequest {
    type Response = GetRemoteHeadersResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.headers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetRemoteHeadersRequest {
            source_shard: ShardId::ROOT,
            from_height: BlockHeight::new(42),
            count: HeaderFetchCount::new(16),
        };

        let encoded = basic_encode(&request).unwrap();
        let decoded: GetRemoteHeadersRequest = basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
