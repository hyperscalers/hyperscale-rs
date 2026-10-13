//! Length-prefixed, compressed stream framing.
//!
//! Shared by both ends of every stream so the wire format cannot drift
//! between them.
//!
//! # Wire formats
//!
//! ## Plain frame (handshake messages, responses)
//! ```text
//! [4-byte BE length][LZ4-compressed payload]
//! ```
//!
//! ## Typed frame (notifications, requests)
//! ```text
//! [2-byte LE type_id_len][type_id bytes][4-byte BE length][LZ4-compressed payload]
//! ```
//!
//! The `type_id` sits outside the compressed payload so the receiver can
//! route a frame to its handler without decompressing first.

use std::{fmt, io};

use hyperscale_network::CompressionError;
use hyperscale_network::compression::{compress, decompress};
use hyperscale_types::MAX_WIRE_MESSAGE_BYTES;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum frame size (compressed), shared across inbound and outbound
/// paths.
///
/// The protocol's own figure: what a block section may be built up to is
/// stated against it, so the two cannot drift apart.
pub const MAX_FRAME_SIZE: usize = MAX_WIRE_MESSAGE_BYTES;

/// Maximum `type_id` length (sanity bound to prevent allocation bombs).
const MAX_TYPE_ID_LEN: usize = 256;

/// Errors from framing operations.
#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    TooLarge(usize),
    Decompress(CompressionError),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "frame I/O error: {e}"),
            Self::TooLarge(len) => write!(f, "frame too large: {len} bytes"),
            Self::Decompress(e) => write!(f, "decompression failed: {e}"),
        }
    }
}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Compress `data`, write it as a length-prefixed frame, and flush.
///
/// Returns the number of bytes written on the wire.
pub async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> Result<usize, io::Error> {
    let compressed = compress(data);
    let len: u32 = compressed.len().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "compressed payload too large for u32 length prefix: {} bytes",
                compressed.len()
            ),
        )
    })?;
    let mut buf = Vec::with_capacity(4 + compressed.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&compressed);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(buf.len())
}

/// Read a length-prefixed, compressed frame of at most `max_size` bytes on
/// the wire and decompress it.
pub async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_size: usize,
) -> Result<Vec<u8>, FrameError> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > max_size {
        return Err(FrameError::TooLarge(len));
    }

    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;

    decompress(&data).map_err(FrameError::Decompress)
}

/// Write a typed frame with an already-compressed payload.
///
/// The caller compresses once; the same bytes then go to every recipient.
/// Returns the number of bytes written on the wire.
pub async fn write_precompressed_typed_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    type_id: &str,
    compressed_data: &[u8],
) -> Result<usize, io::Error> {
    let type_id_bytes = type_id.as_bytes();
    let type_id_len: u16 = type_id_bytes.len().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "type_id too long for u16 length prefix: {} bytes",
                type_id_bytes.len()
            ),
        )
    })?;
    let payload_len: u32 = compressed_data.len().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "compressed payload too large for u32 length prefix: {} bytes",
                compressed_data.len()
            ),
        )
    })?;
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

/// Read a typed frame whose compressed payload is at most `max_size` bytes.
///
/// Returns `(type_id, decompressed_payload, wire_bytes_read)`.
pub async fn read_typed_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_size: usize,
) -> Result<(String, Vec<u8>, usize), FrameError> {
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
            format!("invalid type_id UTF-8: {e}"),
        ))
    })?;

    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let compressed_len = u32::from_be_bytes(len_bytes) as usize;
    if compressed_len > max_size {
        return Err(FrameError::TooLarge(compressed_len));
    }

    let mut compressed = vec![0u8; compressed_len];
    stream.read_exact(&mut compressed).await?;
    let payload = decompress(&compressed).map_err(FrameError::Decompress)?;

    Ok((type_id, payload, 2 + type_id_len + 4 + compressed_len))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[tokio::test]
    async fn a_written_frame_reads_back() {
        let original = b"hello world, this is a framing test";
        let mut buf = Vec::new();
        let written = write_frame(&mut buf, original).await.unwrap();
        assert_eq!(written, buf.len());

        let decoded = read_frame(&mut Cursor::new(buf), 1024).await.unwrap();
        assert_eq!(decoded.as_slice(), original);
    }

    #[tokio::test]
    async fn a_frame_past_the_cap_is_refused_before_its_body_is_read() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &[7u8; 10_000]).await.unwrap();
        let result = read_frame(&mut Cursor::new(buf), 16).await;
        assert!(matches!(result, Err(FrameError::TooLarge(_))));
    }

    #[tokio::test]
    async fn a_truncated_frame_is_an_io_error() {
        let mut buf = 1000u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 10]);
        let result = read_frame(&mut Cursor::new(buf), 4096).await;
        assert!(matches!(result, Err(FrameError::Io(_))));
    }

    #[tokio::test]
    async fn bytes_that_are_not_compressed_data_are_refused() {
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let mut buf = 8u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&garbage);
        let result = read_frame(&mut Cursor::new(buf), 4096).await;
        assert!(matches!(result, Err(FrameError::Decompress(_))));
    }

    #[tokio::test]
    async fn typed_frames_read_back_in_the_order_written() {
        let frames = [
            ("block.header", b"header payload 1" as &[u8]),
            ("block.vote", b"vote payload 2"),
            ("empty", b""),
        ];
        let mut buf = Vec::new();
        let mut written = 0;
        for (type_id, payload) in &frames {
            written += write_precompressed_typed_frame(&mut buf, type_id, &compress(payload))
                .await
                .unwrap();
        }
        assert_eq!(written, buf.len());

        let mut cursor = Cursor::new(buf);
        let mut read = 0;
        for (expected_type_id, expected_payload) in &frames {
            let (type_id, payload, wire_bytes) =
                read_typed_frame(&mut cursor, MAX_FRAME_SIZE).await.unwrap();
            assert_eq!(type_id, *expected_type_id);
            assert_eq!(payload, *expected_payload);
            read += wire_bytes;
        }
        assert_eq!(read, written);

        // The stream ends cleanly between frames.
        let end = read_typed_frame(&mut cursor, MAX_FRAME_SIZE).await;
        assert!(matches!(end, Err(FrameError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof));
    }

    #[tokio::test]
    async fn a_typed_frame_past_the_cap_is_refused() {
        let mut buf = Vec::new();
        write_precompressed_typed_frame(&mut buf, "big", &[0u8; 64])
            .await
            .unwrap();
        let result = read_typed_frame(&mut Cursor::new(buf), 16).await;
        assert!(matches!(result, Err(FrameError::TooLarge(64))));
    }
}
