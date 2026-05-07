//! Merkle inclusion proof for cross-shard provisioning.

use sbor::prelude::*;

use crate::MAX_MERKLE_PROOF_LEN;
use crate::sbor_codec::BoundedBytes;

/// Merkle multiproof authenticating substates' inclusion in the JMT state tree.
///
/// Opaque bytes containing an encoded `hyperscale_jmt::MultiProof`. Encoding,
/// decoding and verification are handled by the storage crate, which owns
/// the adapter between the JMT crate and on-wire SBOR types.
///
/// The proof contains:
/// - Per-claimed-key termination metadata (leaf / empty-subtree / leaf-mismatch)
/// - Sibling hashes for bottom-up verification
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
#[sbor(transparent)]
pub struct MerkleInclusionProof(pub BoundedBytes<MAX_MERKLE_PROOF_LEN>);

impl MerkleInclusionProof {
    /// Create a new proof from raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(BoundedBytes::from(bytes))
    }

    /// Get the raw proof bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create a dummy (empty) proof for testing.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub const fn dummy() -> Self {
        Self(BoundedBytes::new())
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder as _,
        NoCustomValueKind, ValueKind, VecEncoder, basic_decode, basic_encode,
    };

    use super::*;

    #[test]
    fn roundtrip_preserves_bytes() {
        let proof = MerkleInclusionProof::new(vec![0xab; 1024]);
        let bytes = basic_encode(&proof).unwrap();
        let decoded: MerkleInclusionProof = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn decode_rejects_oversized_proof() {
        let mut buf = Vec::with_capacity(32);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ValueKind::U8).unwrap();
        enc.write_size(MAX_MERKLE_PROOF_LEN + 1).unwrap();
        let err = basic_decode::<MerkleInclusionProof>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_MERKLE_PROOF_LEN,
                actual,
            } if actual == MAX_MERKLE_PROOF_LEN + 1
        ));
    }
}
