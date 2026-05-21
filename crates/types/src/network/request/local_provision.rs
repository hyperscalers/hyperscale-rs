//! Local provisions fetch request (intra-shard DA).

use sbor::prelude::BasicSbor;

use crate::network::response::GetLocalProvisionsResponse;
use crate::{MessageClass, NetworkMessage, ProvisionHash, Request};

/// Request to fetch provision batches by hash.
///
/// Used when a validator is missing provisions referenced by a pending
/// block. The responder resolves each hash from the local provision store
/// — no scope information is needed.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetLocalProvisionsRequest {
    /// Hashes of the provisions being requested.
    pub batch_hashes: Vec<ProvisionHash>,
}

impl GetLocalProvisionsRequest {
    /// Build a request for the listed `batch_hashes`.
    #[must_use]
    pub const fn new(batch_hashes: Vec<ProvisionHash>) -> Self {
        Self { batch_hashes }
    }
}

impl NetworkMessage for GetLocalProvisionsRequest {
    fn message_type_id() -> &'static str {
        "local_provision.request"
    }

    fn class() -> MessageClass {
        MessageClass::BlockCompletion
    }
}

impl Request for GetLocalProvisionsRequest {
    type Response = GetLocalProvisionsResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::Hash;

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetLocalProvisionsRequest {
            batch_hashes: vec![
                ProvisionHash::from_raw(Hash::from_bytes(b"batch1")),
                ProvisionHash::from_raw(Hash::from_bytes(b"batch2")),
            ],
        };
        let encoded = basic_encode(&request).unwrap();
        let decoded: GetLocalProvisionsRequest = basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
