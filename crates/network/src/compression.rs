//! LZ4 compression for network messages.
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

/// Maximum decompressed payload size (64 MB).
///
/// Prevents allocation bombs where a small compressed frame claims a huge
/// uncompressed size in its LZ4 header. The compressed wire frame is already
/// capped at 10 MB; 64 MB allows for highly compressible SBOR payloads while
/// blocking multi-GB allocations from malicious peers.
pub const MAX_DECOMPRESSED_SIZE: usize = 64 * 1024 * 1024;

/// Errors from compression/decompression.
#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("decompression failed: {0}")]
    DecompressionFailed(String),

    #[error("claimed uncompressed size {0} exceeds limit {1}")]
    TooLarge(usize, usize),
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
/// Rejects payloads whose claimed uncompressed size exceeds
/// [`MAX_DECOMPRESSED_SIZE`] to prevent allocation bombs.
#[inline]
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let (claimed_size, _) = lz4_flex::block::uncompressed_size(data)
        .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;

    if claimed_size > MAX_DECOMPRESSED_SIZE {
        return Err(CompressionError::TooLarge(
            claimed_size,
            MAX_DECOMPRESSED_SIZE,
        ));
    }

    lz4_flex::decompress_size_prepended(data)
        .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))
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
    fn test_rejects_forged_huge_uncompressed_size() {
        // Craft a payload that claims a 128 MB uncompressed size but contains
        // only a tiny compressed body. This simulates an allocation bomb.
        let fake_size: u32 = 128 * 1024 * 1024;
        let mut malicious = fake_size.to_le_bytes().to_vec();
        malicious.extend_from_slice(&[0u8; 16]); // garbage compressed body
        let err = decompress(&malicious).unwrap_err();
        assert!(
            matches!(err, CompressionError::TooLarge(claimed, _) if claimed == fake_size as usize),
        );
    }

    #[test]
    fn test_compress_decompress_large_payload() {
        // ~1MB of semi-realistic data
        let original: Vec<u8> = (0..1_000_000).map(|i| (i % 251) as u8).collect();
        let compressed = compress(&original);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(original, decompressed);
    }
}
