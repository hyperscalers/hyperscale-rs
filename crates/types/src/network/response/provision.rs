//! Provision fetch response for fallback recovery.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{MessageClass, NetworkMessage, Provisions};

/// Response to a provision fetch request containing the provisions bundle.
///
/// The source shard builds the same `Provisions` bundle the proposer would
/// have broadcast for the requested (block, `target_shard`) pair. The target
/// shard feeds it into the normal verification pipeline (QC + merkle proof
/// checks).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetProvisionResponse {
    /// The provisions bundle for the requested block and target shard.
    ///
    /// - `Some(provisions)` — successfully built bundle (may be empty if no
    ///   matching transactions target the requesting shard).
    /// - `None` — the source shard cannot serve this request (block not
    ///   found, or the historical state version has been garbage-collected).
    ///   The requester should try a different peer.
    ///
    /// `Arc`-wrapped to keep server-side cache hits and dedup-slot transit
    /// from deep-cloning the merkle proof + per-tx entries.
    pub provisions: Option<Arc<Provisions>>,
}

impl NetworkMessage for GetProvisionResponse {
    fn message_type_id() -> &'static str {
        "provision.response"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;

    #[test]
    fn test_sbor_roundtrip_unavailable() {
        let response = GetProvisionResponse { provisions: None };

        let encoded = basic_encode(&response).unwrap();
        let decoded: GetProvisionResponse = basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
