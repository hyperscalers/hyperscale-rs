//! Local provisions fetch response (intra-shard DA).

use hyperscale_types::{MessagePriority, NetworkMessage, ProvisionHash, Provisions};
use sbor::prelude::BasicSbor;

/// Response to a local provisions fetch request.
///
/// `batches` holds the batches the responder has. `missing_hashes` lists the
/// requested hashes the responder does not have (either never seen or evicted
/// from the in-memory store). The union of batch hashes and `missing_hashes`
/// equals the requested hash set, so the caller can distinguish "peer has no
/// copy" from a transport-level empty response.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetLocalProvisionsResponse {
    /// Provision batches the responder had locally.
    pub batches: Vec<Provisions>,
    /// Requested hashes the responder did not have (never seen or evicted).
    pub missing_hashes: Vec<ProvisionHash>,
}

impl GetLocalProvisionsResponse {
    /// Build a response carrying `batches` and a list of `missing_hashes`.
    #[must_use]
    pub const fn new(batches: Vec<Provisions>, missing_hashes: Vec<ProvisionHash>) -> Self {
        Self {
            batches,
            missing_hashes,
        }
    }

    /// Build an empty response (responder had none of the requested batches).
    #[must_use]
    pub const fn empty() -> Self {
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
