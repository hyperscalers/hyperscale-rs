//! Provision fetch response for fallback recovery.

use hyperscale_types::{MessagePriority, NetworkMessage, StateProvision, VerkleInclusionProof};
use sbor::prelude::BasicSbor;

/// Response to a provision fetch request containing the state provisions.
///
/// The source shard builds `StateProvision`s for the requested block and
/// target shard, identical to what the proposer would have broadcast.
/// The target shard feeds these into the normal verification pipeline
/// (QC + merkle proof checks).
///
/// The aggregated verkle proof is stored once at the response level,
/// not per-provision.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetProvisionResponse {
    /// The provisions for the requested block and target shard.
    ///
    /// - `Some(provisions)` — successfully built provisions (may be empty if no
    ///   matching transactions target the requesting shard).
    /// - `None` — the source shard cannot serve this request (block not found,
    ///   or the historical state version has been garbage-collected). The
    ///   requester should try a different peer.
    pub provisions: Option<Vec<StateProvision>>,

    /// Aggregated verkle proof covering all entries across all provisions.
    ///
    /// `None` when `provisions` is `None` or `Some(empty)`.
    pub proof: Option<VerkleInclusionProof>,
}

impl NetworkMessage for GetProvisionResponse {
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

    #[test]
    fn test_sbor_roundtrip_empty() {
        let response = GetProvisionResponse {
            provisions: Some(vec![]),
            proof: None,
        };

        let encoded = sbor::basic_encode(&response).unwrap();
        let decoded: GetProvisionResponse = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_sbor_roundtrip_unavailable() {
        let response = GetProvisionResponse {
            provisions: None,
            proof: None,
        };

        let encoded = sbor::basic_encode(&response).unwrap();
        let decoded: GetProvisionResponse = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
