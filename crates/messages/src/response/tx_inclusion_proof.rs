//! Transaction inclusion proof response for livelock deferral verification.

use hyperscale_types::{Hash, MessagePriority, NetworkMessage, TransactionInclusionProof};
use sbor::prelude::BasicSbor;

/// Response containing a merkle inclusion proof for a transaction.
///
/// The proof can be verified against the block header's `transaction_root`
/// (which is QC-attested). If the transaction is not in the block or the
/// block is not available, both fields are `None`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetTxInclusionProofResponse {
    /// Merkle inclusion proof, if the transaction was found in the block.
    pub proof: Option<TransactionInclusionProof>,
    /// Tagged leaf hash: `hash(TAG || tx_hash)`.
    pub leaf_hash: Option<Hash>,
}

impl NetworkMessage for GetTxInclusionProofResponse {
    fn message_type_id() -> &'static str {
        "tx_inclusion_proof.response"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbor_roundtrip_some() {
        let response = GetTxInclusionProofResponse {
            proof: Some(TransactionInclusionProof {
                siblings: vec![Hash::from_bytes(b"sib1"), Hash::from_bytes(b"sib2")],
                leaf_index: 3,
            }),
            leaf_hash: Some(Hash::from_bytes(b"leaf")),
        };

        let encoded = sbor::basic_encode(&response).unwrap();
        let decoded: GetTxInclusionProofResponse = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_sbor_roundtrip_none() {
        let response = GetTxInclusionProofResponse {
            proof: None,
            leaf_hash: None,
        };

        let encoded = sbor::basic_encode(&response).unwrap();
        let decoded: GetTxInclusionProofResponse = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
