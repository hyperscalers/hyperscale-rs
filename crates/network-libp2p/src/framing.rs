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
