//! Transaction inclusion proof request for livelock deferral verification.

use crate::response::GetTxInclusionProofResponse;
use hyperscale_types::{BlockHeight, Hash, MessagePriority, NetworkMessage, Request};
use sbor::prelude::BasicSbor;

/// Request merkle inclusion proofs for one or more transactions in a committed block.
///
/// Used by the livelock system when cycles are detected and by the priority
/// transaction path under backpressure. Multiple proofs from the same block
/// are batched into a single request to reduce message overhead.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetTxInclusionProofRequest {
    /// Height of the block containing the transactions.
    pub block_height: BlockHeight,
    /// Hashes of the transactions to prove inclusion for.
    pub tx_hashes: Vec<Hash>,
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
            tx_hashes: vec![
                Hash::from_bytes(b"winner_tx_1"),
                Hash::from_bytes(b"winner_tx_2"),
            ],
        };

        let encoded = sbor::basic_encode(&request).unwrap();
        let decoded: GetTxInclusionProofRequest = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn test_sbor_roundtrip_single() {
        let request = GetTxInclusionProofRequest {
            block_height: BlockHeight(10),
            tx_hashes: vec![Hash::from_bytes(b"single_tx")],
        };

        let encoded = sbor::basic_encode(&request).unwrap();
        let decoded: GetTxInclusionProofRequest = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
