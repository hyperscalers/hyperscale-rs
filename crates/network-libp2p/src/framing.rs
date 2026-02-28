//! Length-prefixed, compressed stream framing.
//!
//! Shared by both the inbound router (server) and request manager (client)
//! to ensure the wire protocol cannot drift between the two sides.
//!
//! # Wire format
//!
//! ```text
//! [4-byte big-endian length][LZ4-compressed payload]
//! ```

use futures::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use hyperscale_network::wire;
use std::io;

/// Maximum frame size (compressed), shared across inbound and outbound paths.
pub(crate) const MAX_FRAME_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Errors from framing operations.
#[derive(Debug)]
pub(crate) enum FrameError {
    Io(io::Error),
    TooLarge(usize),
    Decompress(hyperscale_network::wire::WireError),
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
pub(crate) async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> Result<(), io::Error> {
    let compressed = wire::compress(data);
    let len = compressed.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&compressed).await?;
    stream.flush().await?;
    stream.close().await?;
    Ok(())
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

    wire::decompress(&data).map_err(FrameError::Decompress)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a frame into a Vec buffer, then read it back from a cursor.
    /// `write_frame` calls close() so we can't use the same stream for both.
    async fn write_to_buf(data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let compressed = wire::compress(data);
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
}
