//! Transaction inclusion proof response for livelock deferral verification.

use hyperscale_types::{Hash, MessagePriority, NetworkMessage, TransactionInclusionProof};
use sbor::prelude::BasicSbor;

/// A single entry in a batched inclusion proof response.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TxInclusionProofEntry {
    /// Hash of the transaction this proof is for.
    pub tx_hash: Hash,
    /// Merkle inclusion proof, if the transaction was found in the block.
    pub proof: Option<TransactionInclusionProof>,
}

/// Response containing merkle inclusion proofs for one or more transactions.
///
/// Each requested transaction gets an entry. If a transaction is not in the
/// block or the block is not available, its entry has `proof: None`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetTxInclusionProofResponse {
    /// Per-transaction inclusion proofs.
    pub proofs: Vec<TxInclusionProofEntry>,
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
    fn test_sbor_roundtrip_batch() {
        let response = GetTxInclusionProofResponse {
            proofs: vec![
                TxInclusionProofEntry {
                    tx_hash: Hash::from_bytes(b"tx1"),
                    proof: Some(TransactionInclusionProof {
                        siblings: vec![Hash::from_bytes(b"sib1"), Hash::from_bytes(b"sib2")],
                        leaf_index: 3,
                        leaf_hash: Hash::from_bytes(b"leaf1"),
                    }),
                },
                TxInclusionProofEntry {
                    tx_hash: Hash::from_bytes(b"tx2"),
                    proof: None,
                },
            ],
        };

        let encoded = sbor::basic_encode(&response).unwrap();
        let decoded: GetTxInclusionProofResponse = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_sbor_roundtrip_empty() {
        let response = GetTxInclusionProofResponse { proofs: vec![] };

        let encoded = sbor::basic_encode(&response).unwrap();
        let decoded: GetTxInclusionProofResponse = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
