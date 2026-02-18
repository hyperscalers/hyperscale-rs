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
}
