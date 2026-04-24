//! Local provision batch fetch response (intra-shard DA).

use hyperscale_types::{MessagePriority, NetworkMessage, Provision, ProvisionHash};
use sbor::prelude::BasicSbor;

/// Response to a local provision batch fetch request.
///
/// `batches` holds the batches the responder has. `missing_hashes` lists the
/// requested hashes the responder does not have (either never seen or evicted
/// from the in-memory store). The union of batch hashes and `missing_hashes`
/// equals the requested hash set, so the caller can distinguish "peer has no
/// copy" from a transport-level empty response.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetLocalProvisionsResponse {
    pub batches: Vec<Provision>,
    pub missing_hashes: Vec<ProvisionHash>,
}

impl GetLocalProvisionsResponse {
    pub fn new(batches: Vec<Provision>, missing_hashes: Vec<ProvisionHash>) -> Self {
        Self {
            batches,
            missing_hashes,
        }
    }

    pub fn empty() -> Self {
        Self {
            batches: vec![],
            missing_hashes: vec![],
        }
    }
}

impl NetworkMessage for GetLocalProvisionsResponse {
    fn message_type_id() -> &'static str {
        "local_provision.response"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_response() {
        let resp = GetLocalProvisionsResponse::empty();
        assert!(resp.batches.is_empty());
    }
}
