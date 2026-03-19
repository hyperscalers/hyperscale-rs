//! Provision fetch response for fallback recovery.

use hyperscale_codec as sbor;
use hyperscale_codec::BasicSbor;
use hyperscale_types::{MessagePriority, NetworkMessage, StateProvision};

/// Response to a provision fetch request containing the state provisions.
///
/// The source shard builds `StateProvision`s for the requested block and
/// target shard, identical to what the proposer would have broadcast.
/// The target shard feeds these into the normal verification pipeline
/// (QC + merkle proof checks).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetProvisionsResponse {
    /// The provisions for the requested block and target shard.
    ///
    /// - `Some(provisions)` — successfully built provisions (may be empty if no
    ///   matching transactions target the requesting shard).
    /// - `None` — the source shard cannot serve this request (block not found,
    ///   or the historical state version has been garbage-collected). The
    ///   requester should try a different peer.
    pub provisions: Option<Vec<StateProvision>>,
}

impl NetworkMessage for GetProvisionsResponse {
    fn message_type_id() -> &'static str {
        "provision.response"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_codec::{basic_decode, basic_encode};

    #[test]
    fn test_sbor_roundtrip_empty() {
        let response = GetProvisionsResponse {
            provisions: Some(vec![]),
        };

        let encoded = basic_encode(&response).unwrap();
        let decoded: GetProvisionsResponse = basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_sbor_roundtrip_unavailable() {
        let response = GetProvisionsResponse { provisions: None };

        let encoded = basic_encode(&response).unwrap();
        let decoded: GetProvisionsResponse = basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
