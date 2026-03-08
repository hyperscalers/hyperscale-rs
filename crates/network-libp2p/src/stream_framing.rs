//! Length-prefixed, compressed stream framing.
//!
//! Shared by both the inbound router (server) and request manager (client)
//! to ensure the wire protocol cannot drift between the two sides.
//!
//! # Wire formats
//!
//! ## Plain frame (responses)
//! ```text
//! [4-byte BE length][LZ4-compressed payload]
//! ```
//!
//! ## Typed frame (requests)
//! ```text
//! [2-byte LE type_id_len][type_id bytes][4-byte BE length][LZ4-compressed SBOR]
//! ```
//!
//! The type_id sits outside the compressed payload so the receiver can route
//! requests to per-type handlers without decompressing first.

use futures::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use hyperscale_network::compression;
use std::io;

/// Maximum frame size (compressed), shared across inbound and outbound paths.
pub(crate) const MAX_FRAME_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Errors from framing operations.
#[derive(Debug)]
pub(crate) enum FrameError {
    Io(io::Error),
    TooLarge(usize),
    Decompress(hyperscale_network::CompressionError),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "frame I/O error: {}", e),
            FrameError::TooLarge(len) => write!(f, "frame too large: {} bytes", len),
            FrameError::Decompress(e) => write!(f, "decompression failed: {}", e),
        }
    }
}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// Compress `data`, write it as a length-prefixed frame, flush, and close the write side.
///
/// Returns the number of bytes written on the wire (length prefix + compressed payload).
pub(crate) async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> Result<usize, io::Error> {
    let compressed = compression::compress(data);
    let len = compressed.len() as u32;
    let mut buf = Vec::with_capacity(4 + compressed.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&compressed);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    stream.close().await?;
    Ok(buf.len())
}

/// Read a length-prefixed, compressed frame and decompress it.
///
/// Uses `read_exact` — suitable for small-to-moderate messages where a single
/// timeout around the whole call is sufficient (e.g. inbound requests).
pub(crate) async fn read_frame<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    max_size: usize,
) -> Result<Vec<u8>, FrameError> {
    let len = read_frame_len(stream, max_size).await?;

    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;

    compression::decompress(&data).map_err(FrameError::Decompress)
}

/// Read the 4-byte length prefix and validate against `max_size`.
///
/// Returns the frame body length (compressed). For callers that need a custom
/// read strategy (e.g. chunked reads with per-chunk timeout extension).
pub(crate) async fn read_frame_len<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    max_size: usize,
) -> Result<usize, FrameError> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > max_size {
        return Err(FrameError::TooLarge(len));
    }

    Ok(len)
}

/// Maximum type_id length (sanity bound to prevent allocation bombs).
const MAX_TYPE_ID_LEN: usize = 256;

/// Write a typed request frame: type_id header followed by compressed SBOR payload.
///
/// Flushes and half-closes the write side so the receiver knows the request is complete.
/// Returns the number of bytes written on the wire.
pub(crate) async fn write_typed_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    type_id: &str,
    sbor_data: &[u8],
) -> Result<usize, io::Error> {
    let wire_bytes = write_typed_frame_no_close(stream, type_id, sbor_data).await?;
    stream.close().await?;
    Ok(wire_bytes)
}

/// Write a typed frame WITHOUT closing the stream.
///
/// Used by persistent notification streams where multiple frames are sent over
/// the same stream. Flushes after writing to ensure the frame is delivered
/// immediately, but does NOT half-close the write side.
///
/// Returns the number of bytes written on the wire (type header + compressed payload).
pub(crate) async fn write_typed_frame_no_close<S: AsyncWrite + Unpin>(
    stream: &mut S,
    type_id: &str,
    sbor_data: &[u8],
) -> Result<usize, io::Error> {
    let compressed = compression::compress(sbor_data);
    write_precompressed_typed_frame_no_close(stream, type_id, &compressed).await
}

/// Write a typed frame with an already-compressed payload, WITHOUT closing the stream.
///
/// Like [`write_typed_frame_no_close`], but skips compression. The caller is
/// responsible for LZ4-compressing the SBOR payload before calling this.
/// This avoids redundant compression when the same payload is sent to many peers.
///
/// Returns the number of bytes written on the wire (type header + compressed payload).
pub(crate) async fn write_precompressed_typed_frame_no_close<S: AsyncWrite + Unpin>(
    stream: &mut S,
    type_id: &str,
    compressed_data: &[u8],
) -> Result<usize, io::Error> {
    let type_id_bytes = type_id.as_bytes();
    let type_id_len = type_id_bytes.len() as u16;
    let payload_len = compressed_data.len() as u32;
    let wire_len = 2 + type_id_bytes.len() + 4 + compressed_data.len();

    let mut buf = Vec::with_capacity(wire_len);
    buf.extend_from_slice(&type_id_len.to_le_bytes());
    buf.extend_from_slice(type_id_bytes);
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.extend_from_slice(compressed_data);

    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(wire_len)
}

/// Read a typed request frame: type_id header followed by compressed SBOR payload.
///
/// Returns `(type_id, decompressed_payload, wire_bytes_read)`.
pub(crate) async fn read_typed_frame<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    max_size: usize,
) -> Result<(String, Vec<u8>, usize), FrameError> {
    // Read type-id header
    let mut type_id_len_bytes = [0u8; 2];
    stream.read_exact(&mut type_id_len_bytes).await?;
    let type_id_len = u16::from_le_bytes(type_id_len_bytes) as usize;

    if type_id_len > MAX_TYPE_ID_LEN {
        return Err(FrameError::TooLarge(type_id_len));
    }

    let mut type_id_bytes = vec![0u8; type_id_len];
    stream.read_exact(&mut type_id_bytes).await?;
    let type_id = String::from_utf8(type_id_bytes).map_err(|e| {
        FrameError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid type_id UTF-8: {}", e),
        ))
    })?;

    // Read compressed payload length
    let compressed_len = read_frame_len(stream, max_size).await?;

    // Read compressed payload body
    let mut compressed = vec![0u8; compressed_len];
    stream.read_exact(&mut compressed).await?;

    let payload = compression::decompress(&compressed).map_err(FrameError::Decompress)?;

    // Wire bytes: 2 (type_id_len) + type_id + 4 (payload_len) + compressed payload
    let wire_bytes = 2 + type_id_len + 4 + compressed_len;

    Ok((type_id, payload, wire_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a frame into a Vec buffer, then read it back from a cursor.
    /// `write_frame` calls close() so we can't use the same stream for both.
    async fn write_to_buf(data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let compressed = compression::compress(data);
        let len = compressed.len() as u32;
        // Manually write instead of write_frame (which calls close)
        futures::AsyncWriteExt::write_all(&mut buf, &len.to_be_bytes())
            .await
            .unwrap();
        futures::AsyncWriteExt::write_all(&mut buf, &compressed)
            .await
            .unwrap();
        buf
    }

    #[tokio::test]
    async fn test_write_read_frame_roundtrip() {
        let original = b"hello world, this is a framing test";
        let buf = write_to_buf(original).await;
        let mut cursor = futures::io::Cursor::new(buf);
        let decoded = read_frame(&mut cursor, MAX_FRAME_SIZE).await.unwrap();
        assert_eq!(decoded.as_slice(), original);
    }

    #[tokio::test]
    async fn test_write_read_frame_large_payload() {
        let original: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        let buf = write_to_buf(&original).await;
        let mut cursor = futures::io::Cursor::new(buf);
        let decoded = read_frame(&mut cursor, MAX_FRAME_SIZE).await.unwrap();
        assert_eq!(decoded, original);
    }

    #[tokio::test]
    async fn test_read_frame_too_large() {
        // Write a frame with compressed size > max_size
        let data = vec![0u8; 10_000];
        let buf = write_to_buf(&data).await;
        let mut cursor = futures::io::Cursor::new(buf);
        // Use a very small max_size
        let result = read_frame(&mut cursor, 16).await;
        assert!(matches!(result, Err(FrameError::TooLarge(_))));
    }

    #[tokio::test]
    async fn test_read_frame_empty_stream() {
        let mut cursor = futures::io::Cursor::new(Vec::<u8>::new());
        let result = read_frame(&mut cursor, MAX_FRAME_SIZE).await;
        assert!(matches!(result, Err(FrameError::Io(_))));
    }

    #[tokio::test]
    async fn test_read_frame_truncated_body() {
        // Write length header for 1000 bytes but only 10 bytes of body
        let mut buf = Vec::new();
        futures::AsyncWriteExt::write_all(&mut buf, &1000u32.to_be_bytes())
            .await
            .unwrap();
        buf.extend_from_slice(&[0u8; 10]);

        let mut cursor = futures::io::Cursor::new(buf);
        let result = read_frame(&mut cursor, MAX_FRAME_SIZE).await;
        assert!(matches!(result, Err(FrameError::Io(_))));
    }

    #[tokio::test]
    async fn test_read_frame_invalid_compressed_data() {
        // Write valid length prefix + garbage bytes
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let mut buf = Vec::new();
        futures::AsyncWriteExt::write_all(&mut buf, &(garbage.len() as u32).to_be_bytes())
            .await
            .unwrap();
        buf.extend_from_slice(&garbage);

        let mut cursor = futures::io::Cursor::new(buf);
        let result = read_frame(&mut cursor, MAX_FRAME_SIZE).await;
        assert!(matches!(result, Err(FrameError::Decompress(_))));
    }

    #[tokio::test]
    async fn test_read_frame_len_validates_size() {
        // Write a 4-byte length header for 20MB
        let large_len = 20 * 1024 * 1024u32;
        let mut buf = Vec::new();
        futures::AsyncWriteExt::write_all(&mut buf, &large_len.to_be_bytes())
            .await
            .unwrap();

        let mut cursor = futures::io::Cursor::new(buf);
        let result = read_frame_len(&mut cursor, MAX_FRAME_SIZE).await;
        assert!(matches!(result, Err(FrameError::TooLarge(len)) if len == large_len as usize));
    }

    /// Build a typed frame buffer (without calling close) for read tests.
    async fn write_typed_to_buf(type_id: &str, sbor_data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let type_id_bytes = type_id.as_bytes();
        let type_id_len = type_id_bytes.len() as u16;
        futures::AsyncWriteExt::write_all(&mut buf, &type_id_len.to_le_bytes())
            .await
            .unwrap();
        futures::AsyncWriteExt::write_all(&mut buf, type_id_bytes)
            .await
            .unwrap();
        let compressed = compression::compress(sbor_data);
        let len = compressed.len() as u32;
        futures::AsyncWriteExt::write_all(&mut buf, &len.to_be_bytes())
            .await
            .unwrap();
        futures::AsyncWriteExt::write_all(&mut buf, &compressed)
            .await
            .unwrap();
        buf
    }

    #[tokio::test]
    async fn test_typed_frame_roundtrip() {
        let type_id = "block.request";
        let payload = b"some sbor data here";
        let buf = write_typed_to_buf(type_id, payload).await;
        let expected_wire_bytes = buf.len();
        let mut cursor = futures::io::Cursor::new(buf);
        let (parsed_type_id, parsed_payload, wire_bytes) =
            read_typed_frame(&mut cursor, MAX_FRAME_SIZE).await.unwrap();
        assert_eq!(parsed_type_id, type_id);
        assert_eq!(parsed_payload, payload);
        assert_eq!(wire_bytes, expected_wire_bytes);
    }

    #[tokio::test]
    async fn test_typed_frame_empty_payload() {
        let buf = write_typed_to_buf("test", b"").await;
        let mut cursor = futures::io::Cursor::new(buf);
        let (type_id, payload, _wire_bytes) =
            read_typed_frame(&mut cursor, MAX_FRAME_SIZE).await.unwrap();
        assert_eq!(type_id, "test");
        assert!(payload.is_empty());
    }

    #[tokio::test]
    async fn test_typed_frame_empty_stream() {
        let mut cursor = futures::io::Cursor::new(Vec::<u8>::new());
        let result = read_typed_frame(&mut cursor, MAX_FRAME_SIZE).await;
        assert!(matches!(result, Err(FrameError::Io(_))));
    }

    #[tokio::test]
    async fn test_multi_frame_roundtrip() {
        // Simulate persistent stream: write multiple typed frames without
        // closing, then read them back sequentially.
        let frames = [
            ("block.header", b"header payload 1" as &[u8]),
            ("block.vote", b"vote payload 2"),
            ("tx.cert", b"certificate payload 3"),
        ];

        // Write all frames to a single buffer (no close between them).
        let mut buf = Vec::new();
        for (type_id, payload) in &frames {
            write_typed_frame_no_close(&mut buf, type_id, payload)
                .await
                .unwrap();
        }

        // Read them back sequentially from the same cursor.
        let mut cursor = futures::io::Cursor::new(buf);
        for (expected_type_id, expected_payload) in &frames {
            let (type_id, payload, _wire_bytes) =
                read_typed_frame(&mut cursor, MAX_FRAME_SIZE).await.unwrap();
            assert_eq!(type_id, *expected_type_id);
            assert_eq!(payload, *expected_payload);
        }

        // Next read should fail with EOF (no more frames).
        let result = read_typed_frame(&mut cursor, MAX_FRAME_SIZE).await;
        assert!(matches!(result, Err(FrameError::Io(_))));
    }
}
