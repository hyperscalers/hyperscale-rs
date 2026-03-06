//! Stream I/O and speculative retry logic.
//!
//! Handles the low-level mechanics of sending requests over libp2p streams,
//! including typed framing (type_id in header), compression, and speculative
//! retry (racing duplicate requests based on RTT history).

use super::{RequestManager, RequestPriority};
use crate::adapter::{Libp2pAdapter, NetworkError};
use crate::stream_framing::{self, MAX_FRAME_SIZE};
use bytes::Bytes;
use futures::AsyncReadExt;
use hyperscale_metrics as metrics;
use hyperscale_network::compression;
use libp2p::PeerId;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

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

    /// Send a request with speculative retry based on RTT.
    ///
    /// If we have RTT data for the peer, we send a speculative duplicate request
    /// after `RTT * multiplier` to race against packet loss. Both requests are
    /// identical, so the responder returns the same data and we take whichever
    /// arrives first.
    ///
    /// Returns the response and the actual elapsed time (for RTT tracking).
    pub(super) async fn send_request_with_speculative_retry(
        &self,
        peer: &PeerId,
        type_id: &'static str,
        data: &[u8],
        priority: RequestPriority,
    ) -> Result<(Vec<u8>, Duration), NetworkError> {
        let start = Instant::now();

        // Compute speculative retry timeout based on peer's RTT history
        let speculative_timeout = self.compute_speculative_timeout(peer);

        // If speculative retry is disabled or timeout is too long, just send once
        if self.config.speculative_retry_multiplier == 0.0
            || speculative_timeout >= self.config.speculative_retry_max
        {
            let result = self.send_request(peer, type_id, data, priority).await?;
            return Ok((result, start.elapsed()));
        }

        // Compute stream timeout based on peer RTT (do this before spawning)
        let stream_timeout = self.compute_stream_timeout(peer);
        debug!(
            ?peer,
            stream_timeout_ms = stream_timeout.as_millis(),
            speculative_timeout_ms = speculative_timeout.as_millis(),
            "Computed timeouts for request"
        );

        // Share the request data between both tasks via Bytes (O(1) clone).
        let data_shared: Bytes = Bytes::copy_from_slice(data);

        // Send initial request (as a spawned task so it keeps running even if we move on)
        let adapter_clone = self.adapter.clone();
        let data_first = data_shared.clone();
        let peer_clone = *peer;

        // Spawn the first request so it continues running independently
        let mut first_handle = tokio::spawn(async move {
            Self::send_request_static(
                &adapter_clone,
                &peer_clone,
                type_id,
                &data_first,
                stream_timeout,
            )
            .await
        });

        // Wait for either: first request completes, or speculative timeout
        let sleep = tokio::time::sleep(speculative_timeout);
        tokio::pin!(sleep);

        tokio::select! {
            // First request completes before speculative timeout
            result = &mut first_handle => {
                match result {
                    Ok(Ok(response)) => return Ok((response, start.elapsed())),
                    Ok(Err(e)) => return Err(e),
                    Err(_join_error) => return Err(NetworkError::NetworkShutdown),
                }
            }

            // Speculative timeout elapsed - send second request and race both
            _ = &mut sleep => {
                trace!(
                    peer = ?peer,
                    speculative_timeout_ms = speculative_timeout.as_millis(),
                    "Sending speculative retry"
                );
            }
        }

        // If we get here, speculative timeout fired. Send second request and race both.
        let adapter_clone2 = self.adapter.clone();
        let peer_clone2 = *peer;

        let mut second_handle = tokio::spawn(async move {
            Self::send_request_static(
                &adapter_clone2,
                &peer_clone2,
                type_id,
                &data_shared,
                stream_timeout,
            )
            .await
        });

        // Race both requests - first SUCCESS wins.
        // If one fails, wait for the other. Only return error if both fail.
        let mut first_done = false;
        let mut second_done = false;
        #[allow(unused_assignments)] // False positive: always assigned before loop exit
        let mut last_error: Option<NetworkError> = None;

        loop {
            tokio::select! {
                result = &mut first_handle, if !first_done => {
                    match result {
                        Ok(Ok(response)) => return Ok((response, start.elapsed())),
                        Ok(Err(e)) => {
                            first_done = true;
                            last_error = Some(e);
                        }
                        Err(_) => {
                            first_done = true;
                            last_error = Some(NetworkError::NetworkShutdown);
                        }
                    }
                }
                result = &mut second_handle, if !second_done => {
                    match result {
                        Ok(Ok(response)) => return Ok((response, start.elapsed())),
                        Ok(Err(e)) => {
                            second_done = true;
                            last_error = Some(e);
                        }
                        Err(_) => {
                            second_done = true;
                            last_error = Some(NetworkError::NetworkShutdown);
                        }
                    }
                }
            }

            // Both requests failed - return the last error
            if first_done && second_done {
                return Err(last_error.unwrap_or(NetworkError::Timeout));
            }
        }
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
