//! Committed block header fetch response for fallback recovery.

use hyperscale_types::{CommittedBlockHeader, MessagePriority, NetworkMessage};
use sbor::prelude::BasicSbor;

/// Response to a committed block header fetch request.
///
/// Returns the requested committed block header (header + QC) from the
/// source shard's local storage. `None` means the shard cannot serve
/// this request (block not yet committed, or pruned). The requester
/// should try a different peer.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetCommittedBlockHeaderResponse {
    /// The requested committed block header.
    ///
    /// - `Some(header)` — successfully found the header.
    /// - `None` — the source shard cannot serve this request.
    pub header: Option<CommittedBlockHeader>,
}

impl NetworkMessage for GetCommittedBlockHeaderResponse {
    fn message_type_id() -> &'static str {
        "committed_header.response"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbor_roundtrip_unavailable() {
        let response = GetCommittedBlockHeaderResponse { header: None };

        let encoded = sbor::basic_encode(&response).unwrap();
        let decoded: GetCommittedBlockHeaderResponse = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
