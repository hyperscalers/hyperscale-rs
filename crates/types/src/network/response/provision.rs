//! Provision fetch response for fallback recovery.

use hyperscale_hbor::{Capped, Hbor};

use crate::{MAX_TXS_PER_BLOCK, MessageClass, NetworkMessage, Provision, ProvisionCount};

/// Response to a provision fetch request: the asked parts the source
/// could build, and the count of what the block owes the asker.
///
/// The source shard builds the same parts the proposer would have
/// gossiped. The target shard feeds each into the normal verification
/// pipeline (leaf path, QC and merkle proof checks). An asked index the
/// response leaves out is asked again elsewhere; nothing carries the
/// responder's word that it is unbuildable, because nothing could check
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetProvisionResponse {
    /// The parts built, in leaf order.
    pub parts: Capped<Vec<Provision>, MAX_TXS_PER_BLOCK>,
    /// The count witness: what the block owes the asker, which the
    /// asker checks against the header's root. Any holder of the block
    /// states it, whether or not it builds a single part, so the asker
    /// learns how many parts there are without depending on any one of
    /// them.
    pub count: Option<ProvisionCount>,
}

impl GetProvisionResponse {
    /// An answer carrying nothing.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            parts: Capped::empty(),
            count: None,
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
    use crate::Hash;

    #[test]
    fn test_hbor_roundtrip() {
        for response in [
            GetProvisionResponse::empty(),
            GetProvisionResponse {
                parts: Capped::empty(),
                count: Some(ProvisionCount {
                    count: 3,
                    merkle_root: Hash::from_bytes(b"root"),
                }),
            },
        ] {
            let encoded = hbor_to_vec(&response).unwrap();
            let decoded: GetProvisionResponse = hbor_from_slice(&encoded).unwrap();
            assert_eq!(response, decoded);
        }
    }
}
