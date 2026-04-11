//! Local provision batch fetch response (intra-shard DA).

use hyperscale_types::{MessagePriority, NetworkMessage, Provision};
use sbor::prelude::BasicSbor;

/// Response to a local provision batch fetch request.
///
/// Contains the requested provision batches that the responder has.
/// Missing batches are simply not included in the response.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetLocalProvisionsResponse {
    /// The requested provision batches that were found.
    pub batches: Vec<Provision>,
}

impl GetLocalProvisionsResponse {
    pub fn new(batches: Vec<Provision>) -> Self {
        Self { batches }
    }

    pub fn empty() -> Self {
        Self { batches: vec![] }
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
