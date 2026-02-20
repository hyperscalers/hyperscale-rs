//! Wire format compression for network messages.
//!
//! All network messages (gossip and request/response) are LZ4-compressed
//! to reduce bandwidth and improve reliability under packet loss.
//!
//! # Wire Format
//!
//! ```text
//! [LZ4 compressed data with prepended size]
//! ```
//!
//! The size prefix is part of LZ4's framing - it stores the original
//! uncompressed size so decompression can pre-allocate the output buffer.

use thiserror::Error;

/// Errors from wire encoding/decoding.
#[derive(Debug, Error)]
pub enum WireError {
    #[error("decompression failed: {0}")]
    DecompressionFailed(String),

    #[error("request frame too short")]
    FrameTooShort,

    #[error("invalid type_id: not valid UTF-8")]
    InvalidTypeId,
}

/// Compress data for transmission over the network.
///
/// Uses LZ4 block compression with a prepended size header.
/// LZ4 is chosen for its speed (~400 MB/s) with reasonable ratios (2-3x).
#[inline]
pub fn compress(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

/// Decompress data received from the network.
///
/// Expects LZ4 block format with prepended size header.
#[inline]
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, WireError> {
    lz4_flex::decompress_size_prepended(data)
        .map_err(|e| WireError::DecompressionFailed(e.to_string()))
}

// ═══════════════════════════════════════════════════════════════════════
// Request framing
// ═══════════════════════════════════════════════════════════════════════

/// Frame a request with a type_id prefix for dispatch by the receiver.
///
/// Wire format: `[type_id_len: u16 LE][type_id: UTF-8][SBOR payload]`
///
/// Used by the `Network::request<R>()` sender to tag opaque request bytes
/// with a type identifier. The receiver (`InboundRequestHandler`) calls
/// [`parse_request_frame`] to extract the type_id and dispatch accordingly.
pub fn frame_request(type_id: &str, payload: &[u8]) -> Vec<u8> {
    let type_id_bytes = type_id.as_bytes();
    let type_id_len = type_id_bytes.len() as u16;
    let mut framed = Vec::with_capacity(2 + type_id_bytes.len() + payload.len());
    framed.extend_from_slice(&type_id_len.to_le_bytes());
    framed.extend_from_slice(type_id_bytes);
    framed.extend_from_slice(payload);
    framed
}

/// Parse a framed request into `(type_id, payload)`.
///
/// Inverse of [`frame_request`]. Returns the type identifier string and
/// the remaining SBOR payload bytes.
pub fn parse_request_frame(data: &[u8]) -> Result<(&str, &[u8]), WireError> {
    if data.len() < 2 {
        return Err(WireError::FrameTooShort);
    }
    let type_id_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + type_id_len {
        return Err(WireError::FrameTooShort);
    }
    let type_id =
        std::str::from_utf8(&data[2..2 + type_id_len]).map_err(|_| WireError::InvalidTypeId)?;
    let payload = &data[2 + type_id_len..];
    Ok((type_id, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let original = b"hello world, this is a test message for compression";
        let compressed = compress(original);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(original.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_empty() {
        let original = b"";
        let compressed = compress(original);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(original.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_compressible_data() {
        let original = vec![0u8; 10000];
        let compressed = compress(&original);
        assert!(compressed.len() < original.len() / 2);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(original, decompressed);
    }

    #[test]
    fn test_incompressible_data() {
        let original: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let compressed = compress(&original);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(original, decompressed);
    }

    #[test]
    fn test_invalid_data() {
        let garbage = b"not valid lz4 data";
        assert!(decompress(garbage).is_err());
    }

    #[test]
    fn test_frame_request_roundtrip() {
        let type_id = "block.request";
        let payload = b"some sbor data here";
        let framed = frame_request(type_id, payload);
        let (parsed_type_id, parsed_payload) = parse_request_frame(&framed).unwrap();
        assert_eq!(parsed_type_id, type_id);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_frame_request_empty_payload() {
        let framed = frame_request("test", b"");
        let (type_id, payload) = parse_request_frame(&framed).unwrap();
        assert_eq!(type_id, "test");
        assert!(payload.is_empty());
    }

    #[test]
    fn test_parse_request_frame_too_short() {
        assert!(matches!(
            parse_request_frame(&[]),
            Err(WireError::FrameTooShort)
        ));
        assert!(matches!(
            parse_request_frame(&[1]),
            Err(WireError::FrameTooShort)
        ));
        // type_id_len says 5 but only 2 bytes of type_id available
        assert!(matches!(
            parse_request_frame(&[5, 0, b'a', b'b']),
            Err(WireError::FrameTooShort)
        ));
    }
}
