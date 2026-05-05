//! Merkle inclusion proof for cross-shard provisioning.

use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

/// Cap on a serialized merkle proof at decode time. The proof grows roughly
/// with `claim_count × tree_depth × hash_size`. With JMT decode-time caps
/// of `10_000` claims and `100_000` sibling hashes (32 bytes each),
/// legitimate proofs sit well under 4 MiB; we cap a touch above for headroom.
const MAX_MERKLE_PROOF_LEN: usize = 4 * 1024 * 1024;

/// Merkle multiproof authenticating substates' inclusion in the JMT state tree.
///
/// Opaque bytes containing an encoded `hyperscale_jmt::MultiProof`. Encoding,
/// decoding and verification are handled by the storage crate, which owns
/// the adapter between the JMT crate and on-wire SBOR types.
///
/// The proof contains:
/// - Per-claimed-key termination metadata (leaf / empty-subtree / leaf-mismatch)
/// - Sibling hashes for bottom-up verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleInclusionProof(pub Vec<u8>);

impl MerkleInclusionProof {
    /// Create a new proof from raw bytes.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
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
        Self(Vec::new())
    }
}

// Manual SBOR impls in lieu of `#[sbor(transparent)]` so the inner `Vec<u8>`
// goes through a bounded byte decoder.

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for MerkleInclusionProof {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(<Vec<u8> as Categorize<NoCustomValueKind>>::value_kind())
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        // Mirror SBOR's `Vec<u8>` body: element kind, size, raw bytes.
        encoder.write_value_kind(ValueKind::U8)?;
        encoder.write_size(self.0.len())?;
        encoder.write_slice(&self.0)?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for MerkleInclusionProof {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Array)?;
        decoder.read_and_check_value_kind(ValueKind::U8)?;
        let len = decoder.read_size()?;
        if len > MAX_MERKLE_PROOF_LEN {
            return Err(DecodeError::UnexpectedSize {
                expected: MAX_MERKLE_PROOF_LEN,
                actual: len,
            });
        }
        let slice = decoder.read_slice(len)?;
        Ok(Self(slice.to_vec()))
    }
}

impl Categorize<NoCustomValueKind> for MerkleInclusionProof {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Array
    }
}

impl Describe<NoCustomTypeKind> for MerkleInclusionProof {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("MerkleInclusionProof", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, VecEncoder, basic_decode,
        basic_encode,
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
