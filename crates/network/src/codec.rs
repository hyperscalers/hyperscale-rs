//! Message encoding and decoding for network transport.
//!
//! # Wire Format
//!
//! All gossip messages are SBOR-encoded then LZ4-compressed:
//!
//! ```text
//! [LZ4 compressed SBOR payload]
//! ```
//!
//! This module provides generic encode/decode helpers. Application-level
//! message dispatch (topic → typed message → Event) lives in `hyperscale-node`.

use crate::wire;
use thiserror::Error;

/// Errors that can occur during message encoding/decoding.
#[derive(Debug, Error)]
pub enum CodecError {
    #[error("Message too short")]
    MessageTooShort,

    #[error("SBOR decode error: {0}")]
    SborDecode(String),

    #[error("SBOR encode error: {0}")]
    SborEncode(String),

    #[error("Decompression error: {0}")]
    Decompress(String),

    #[error("Unknown topic: {0}")]
    UnknownTopic(String),
}

/// Encode a value to wire format (SBOR + LZ4 compression).
///
/// This is a generic helper that SBOR-encodes any `BasicEncode` type then
/// LZ4-compresses the result.
pub fn encode_to_wire<T: sbor::BasicEncode>(value: &T) -> Result<Vec<u8>, CodecError> {
    let sbor_bytes =
        sbor::basic_encode(value).map_err(|e| CodecError::SborEncode(format!("{:?}", e)))?;
    Ok(wire::compress(&sbor_bytes))
}

/// Decode a value from wire format (LZ4 decompression + SBOR decode).
///
/// Inverse of [`encode_to_wire`]. Decompresses LZ4 then SBOR-decodes into
/// the target type.
#[cfg(test)]
fn decode_from_wire<T: sbor::BasicDecode>(data: &[u8]) -> Result<T, CodecError> {
    if data.is_empty() {
        return Err(CodecError::MessageTooShort);
    }
    let payload = wire::decompress(data).map_err(|e| CodecError::Decompress(e.to_string()))?;
    sbor::basic_decode(&payload).map_err(|e| CodecError::SborDecode(format!("{:?}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let original: Vec<u8> = vec![1, 2, 3, 4, 5];
        let encoded = encode_to_wire(&original).unwrap();
        let decoded: Vec<u8> = decode_from_wire(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_empty_data_returns_error() {
        let result = decode_from_wire::<Vec<u8>>(&[]);
        assert!(matches!(result, Err(CodecError::MessageTooShort)));
    }

    #[test]
    fn test_invalid_compressed_data() {
        let result = decode_from_wire::<Vec<u8>>(&[99, 1, 2, 3]);
        assert!(matches!(result, Err(CodecError::Decompress(_))));
    }

    #[test]
    fn test_encode_decode_roundtrip_with_real_message() {
        use hyperscale_messages::BlockVoteGossip;
        use hyperscale_types::{
            zero_bls_signature, BlockHeight, BlockVote, Hash, ShardGroupId, ValidatorId,
        };

        let gossip = BlockVoteGossip::new(BlockVote {
            block_hash: Hash::from_bytes(b"test_block"),
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(42),
            round: 1,
            voter: ValidatorId(7),
            signature: zero_bls_signature(),
            timestamp: 1_000_000_000_000,
        });

        let encoded = encode_to_wire(&gossip).unwrap();
        let decoded: BlockVoteGossip = decode_from_wire(&encoded).unwrap();
        assert_eq!(decoded, gossip);
    }

    #[test]
    fn test_decode_truncated_compressed_data() {
        let original: Vec<u8> = vec![1, 2, 3, 4, 5];
        let encoded = encode_to_wire(&original).unwrap();
        // Truncate to half
        let truncated = &encoded[..encoded.len() / 2];
        let result = decode_from_wire::<Vec<u8>>(truncated);
        assert!(matches!(result, Err(CodecError::Decompress(_))));
    }
}
