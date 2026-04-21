//! Stream I/O for the request manager.
//!
//! Handles the low-level mechanics of sending requests over libp2p streams,
//! including typed framing (type_id in header) and compression.

use super::{RequestManager, RequestPriority};
use crate::adapter::{Libp2pAdapter, NetworkError};
use crate::stream_framing::{self, MAX_FRAME_SIZE};
use futures::AsyncReadExt;
use hyperscale_metrics as metrics;
use hyperscale_network::compression;
use libp2p::PeerId;
use std::sync::Arc;
use std::time::Duration;
use tracing::trace;

impl RequestManager {
    /// Send the actual request through the adapter using raw streams.
    ///
    /// Opens a stream, writes a typed frame (type_id + compressed SBOR),
    /// reads the compressed response, all wrapped in timeouts.
    pub(super) async fn send_request(
        &self,
        peer: &PeerId,
        type_id: &'static str,
        data: &[u8],
        _priority: RequestPriority,
    ) -> Result<Vec<u8>, NetworkError> {
        let timeout = self.compute_stream_timeout(peer);
        Self::send_request_static(&self.adapter, peer, type_id, data, timeout).await
    }

    /// Static version of send_request for use in spawned tasks.
    ///
    /// Uses typed framing for requests:
    /// 1. Open stream to peer
    /// 2. Write typed frame: [2B type_id_len][type_id][4B len][LZ4 compressed SBOR]
    /// 3. Read plain frame response: [4B len][LZ4 compressed SBOR]
    /// 4. Decompress response
    ///
    /// All I/O operations are wrapped with the provided timeout (RTT-based).
    async fn send_request_static(
        adapter: &Arc<Libp2pAdapter>,
        peer: &PeerId,
        type_id: &str,
        sbor_data: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, NetworkError> {
        // Open stream with timeout
        let mut stream = tokio::time::timeout(timeout, adapter.open_request_stream(*peer))
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| NetworkError::StreamOpenFailed(format!("{:?}", e)))?;

        // Write typed frame (type_id header + compressed SBOR) with timeout.
        // write_typed_frame flushes and half-closes the write side.
        let write_result = tokio::time::timeout(
            timeout,
            stream_framing::write_typed_frame(&mut stream, type_id, sbor_data),
        )
        .await;

        match write_result {
            Ok(Ok(wire_bytes)) => {
                metrics::record_libp2p_bandwidth(0, wire_bytes as u64);
            }
            Ok(Err(e)) => return Err(NetworkError::StreamIo(format!("write failed: {}", e))),
            Err(_) => return Err(NetworkError::Timeout),
        }

        // Read response length with timeout
        let response_len = match tokio::time::timeout(
            timeout,
            stream_framing::read_frame_len(&mut stream, MAX_FRAME_SIZE),
        )
        .await
        {
            Ok(Ok(len)) => len,
            Ok(Err(e)) => return Err(NetworkError::StreamIo(format!("read length failed: {}", e))),
            Err(_) => return Err(NetworkError::Timeout),
        };

        // Read compressed response body in chunks with activity-based timeout extension.
        // This is critical for large responses under packet loss: QUIC will retransmit
        // dropped packets, but we need to give it time. As long as we're receiving data,
        // we keep extending the deadline.
        let mut compressed_response = Vec::with_capacity(response_len);
        let mut buf = [0u8; 65536]; // 64KB chunks

        while compressed_response.len() < response_len {
            let remaining = response_len - compressed_response.len();
            let to_read = remaining.min(buf.len());

            // Each chunk gets a fresh timeout - activity resets the clock
            let chunk_result =
                tokio::time::timeout(timeout, stream.read(&mut buf[..to_read])).await;

            match chunk_result {
                Ok(Ok(0)) => {
                    // EOF before expected length
                    return Err(NetworkError::StreamIo(format!(
                        "unexpected EOF: got {} of {} bytes",
                        compressed_response.len(),
                        response_len
                    )));
                }
                Ok(Ok(n)) => {
                    compressed_response.extend_from_slice(&buf[..n]);
                    // Timeout resets implicitly by looping - next read gets fresh timeout
                    trace!(
                        bytes_received = compressed_response.len(),
                        bytes_total = response_len,
                        chunk_size = n,
                        "Received chunk, timeout extended"
                    );
                }
                Ok(Err(e)) => {
                    return Err(NetworkError::StreamIo(format!(
                        "read failed at {} of {} bytes: {}",
                        compressed_response.len(),
                        response_len,
                        e
                    )));
                }
                Err(_) => {
                    // Timeout with no activity
                    return Err(NetworkError::Timeout);
                }
            }
        }

        // Record inbound bandwidth: 4-byte length prefix + compressed response body
        metrics::record_libp2p_bandwidth((4 + response_len) as u64, 0);

        // Decompress response
        compression::decompress(&compressed_response)
            .map_err(|e| NetworkError::StreamIo(format!("decompression failed: {}", e)))
    }
}
