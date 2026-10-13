//! Length-prefixed, compressed stream framing.
//!
//! Shared by both ends of every stream so the wire format cannot drift
//! between them.
//!
//! A frame is `[4-byte BE length][LZ4-compressed payload]`.

use std::{fmt, io};

use hyperscale_network::CompressionError;
use hyperscale_network::compression::{compress, decompress};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
}
