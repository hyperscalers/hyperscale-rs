//! Local provisions fetch response (intra-shard DA).

use hyperscale_types::{MessagePriority, NetworkMessage, Provisions};
use sbor::prelude::BasicSbor;

/// Response to a local provisions fetch request.
///
/// `batches` holds the batches the responder has. The requester knows the
/// hashes it asked for, so missing hashes are computed client-side as
/// `requested - returned`; the wire format does not duplicate that diff.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetLocalProvisionsResponse {
    /// Provision batches the responder had locally.
    pub batches: Vec<Provisions>,
}

impl GetLocalProvisionsResponse {
    /// Build a response carrying `batches`.
    #[must_use]
    pub const fn new(batches: Vec<Provisions>) -> Self {
        Self { batches }
    }

    /// Build an empty response (responder had none of the requested batches).
    #[must_use]
    pub const fn empty() -> Self {
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
