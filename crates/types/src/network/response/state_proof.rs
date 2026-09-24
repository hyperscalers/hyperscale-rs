//! Response to a state-proof request: one multiproof over every key
//! asked, with the value of every crossing record it proves present,
//! or nothing when the height is not served here.

use hyperscale_hbor::{Bytes, Capped, Hbor};

use crate::{
    MAX_HELD_VALUE_BYTES, MAX_PROOFS_PER_QUERY, MerkleInclusionProof, MessageClass, NetworkMessage,
    SubstateKey,
};

/// The value a served proof carries for one record cell.
pub type ServedValue = (SubstateKey, Bytes<MAX_HELD_VALUE_BYTES>);

/// The proof, or `None` when this peer does not hold the JMT version
/// the height names — never committed here, or pruned past its history.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetStateProofResponse {
    /// A multiproof over every requested key against the height's root.
    pub proof: Option<MerkleInclusionProof>,
    /// The value of each requested key the proof shows present whose
    /// leaf is a crossing record or its tombstone. The requester holds
    /// each to the proof's presence, so nothing here is trusted.
    pub values: Capped<Vec<ServedValue>, MAX_PROOFS_PER_QUERY>,
}

impl GetStateProofResponse {
    /// A served proof, with the record values it proves present.
    #[must_use]
    pub const fn found(
        proof: MerkleInclusionProof,
        values: Capped<Vec<ServedValue>, MAX_PROOFS_PER_QUERY>,
    ) -> Self {
        Self {
            proof: Some(proof),
            values,
        }
    }

    /// The height is not served here.
    #[must_use]
    pub const fn not_found() -> Self {
        Self {
            proof: None,
            values: Capped::empty(),
        }
    }
}

impl NetworkMessage for GetStateProofResponse {
    fn message_type_id() -> &'static str {
        "state_proof.response"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::test_utils::test_key;

    #[test]
    fn test_hbor_roundtrip() {
        for response in [
            GetStateProofResponse::not_found(),
            GetStateProofResponse::found(MerkleInclusionProof::new(vec![1, 2, 3]), Capped::empty()),
            GetStateProofResponse::found(
                MerkleInclusionProof::new(vec![1, 2, 3]),
                Capped::from_array([(test_key(4), Bytes::new(vec![9; 40]).unwrap())]),
            ),
        ] {
            let encoded = hbor_to_vec(&response).unwrap();
            let decoded: GetStateProofResponse = hbor_from_slice(&encoded).unwrap();
            assert_eq!(response, decoded);
        }
    }
}
