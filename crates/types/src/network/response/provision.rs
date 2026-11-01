//! Provision fetch response for fallback recovery.

use hyperscale_hbor::{Capped, Hbor};

use crate::{MAX_TXS_PER_BLOCK, MessageClass, NetworkMessage, Provision};

/// Response to a provision fetch request: the parts the source could
/// build of what the requested block owes the asker.
///
/// The source shard builds the same parts the proposer would have
/// gossiped for the requested (block, `target_shard`) pair. The target
/// shard feeds each into the normal verification pipeline (leaf path,
/// QC and merkle proof checks). No parts means the source does not hold
/// the block or could build none of them; the requester asks another
/// peer.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetProvisionResponse {
    /// The parts built, in leaf order.
    pub parts: Capped<Vec<Provision>, MAX_TXS_PER_BLOCK>,
}

impl GetProvisionResponse {
    /// An answer carrying nothing.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            parts: Capped::empty(),
        }
    }
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
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    #[test]
    fn test_hbor_roundtrip_unavailable() {
        let response = GetProvisionResponse::empty();

        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetProvisionResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
