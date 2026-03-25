//! Transaction inclusion proof request for livelock deferral verification.

use crate::response::GetTxInclusionProofResponse;
use hyperscale_types::{BlockHeight, Hash, MessagePriority, NetworkMessage, Request};
use sbor::prelude::BasicSbor;

/// Request a merkle inclusion proof for a transaction in a committed block.
///
/// Used by the livelock system when a cycle is detected. The requesting shard
/// needs proof that the winner transaction was included in a committed block
/// on the source shard, verified against the block header's `transaction_root`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetTxInclusionProofRequest {
    /// Height of the block containing the transaction.
    pub block_height: BlockHeight,
    /// Hash of the transaction to prove inclusion for.
    pub tx_hash: Hash,
}

impl NetworkMessage for GetTxInclusionProofRequest {
    fn message_type_id() -> &'static str {
        "tx_inclusion_proof.request"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

impl Request for GetTxInclusionProofRequest {
    type Response = GetTxInclusionProofResponse;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetTxInclusionProofRequest {
            block_height: BlockHeight(42),
            tx_hash: Hash::from_bytes(b"winner_tx"),
        };

        let encoded = sbor::basic_encode(&request).unwrap();
        let decoded: GetTxInclusionProofRequest = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
