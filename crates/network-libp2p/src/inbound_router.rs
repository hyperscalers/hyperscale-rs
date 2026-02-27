//! Routes inbound network requests to appropriate handlers.
//!
//! This component accepts incoming streams from peers and routes them to the
//! appropriate handler based on request type. It unifies the handling of:
//! - Block sync requests
//! - Transaction fetch requests
//! - Certificate fetch requests
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────┐
//! │                         libp2p_stream                                      │
//! │  ┌─────────────────────────────────────────────────────────────────────┐   │
//! │  │  Incoming Stream                                                    │   │
//! │  │  (bidirectional raw stream)                                         │   │
//! │  └───────────────────────────────┬─────────────────────────────────────┘   │
//! └──────────────────────────────────┼─────────────────────────────────────────┘
//!                                    │
//!                                    ▼
//! ┌────────────────────────────────────────────────────────────────────────────┐
//! │                         InboundRouter<H>                                   │
//! │                                                                            │
//! │  Transport: read/write length-prefixed, compressed streams                │
//! │  Logic:     delegates to H: InboundRequestHandler                         │
//! │                                                                            │
//! └────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Design Goals
//!
//! 1. **Separation of Concerns**: Transport handles framing/compression, handler handles request logic
//! 2. **Request-Response via Streams**: Uses raw libp2p streams with length-prefixed framing
//! 3. **Generic over Handler**: Parameterized over `InboundRequestHandler`, no app-type dependency

use crate::adapter::{Libp2pAdapter, STREAM_PROTOCOL};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use hyperscale_network::{wire, InboundRequestHandler};
use libp2p::{PeerId, Stream};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Timeout for reading requests and writing responses on streams.
const STREAM_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum request size (10MB).
const MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024;

/// Handle for the inbound router task.
///
/// Kept alive inside `ProdNetwork` to prevent the tokio task from being
/// aborted when the `JoinHandle` is dropped.
pub(crate) struct InboundRouterHandle {
    #[allow(dead_code)]
    join_handle: tokio::task::JoinHandle<()>,
}

/// Routes inbound requests to an application-level handler.
///
/// The router accepts incoming streams and for each:
/// 1. Reads the length-prefixed compressed request
/// 2. Decompresses and delegates to `H` for processing
/// 3. Compresses and writes the length-prefixed response
/// 4. Closes the stream
///
/// Generic over `H: InboundRequestHandler` — the concrete handler is supplied
/// by the production runner when constructing the router.
struct InboundRouter<H: InboundRequestHandler> {
    handler: H,
}

impl<H: InboundRequestHandler> InboundRouter<H> {
    /// Spawn the inbound router as a background task.
    ///
    /// The router will accept incoming streams until the stream control is dropped.
    fn spawn(adapter: Arc<Libp2pAdapter>, handler: H) -> InboundRouterHandle {
        let join_handle = tokio::spawn(async move {
            let router = Arc::new(InboundRouter { handler });
            let mut control = adapter.stream_control();

            // Register to accept incoming streams for our protocol
            let mut incoming = match control.accept(STREAM_PROTOCOL) {
                Ok(incoming) => incoming,
                Err(e) => {
                    tracing::error!(error = ?e, "Failed to register stream protocol");
                    return;
                }
            };

            tracing::info!("InboundRouter started, accepting incoming streams");

            // Accept incoming streams
            while let Some((peer_id, stream)) = incoming.next().await {
                let router_clone = router.clone();

                // Spawn a task to handle each stream concurrently
                tokio::spawn(async move {
                    if let Err(e) = router_clone.handle_stream(peer_id, stream).await {
                        debug!(peer = %peer_id, error = ?e, "Stream handling failed");
                    }
                });
            }

            tracing::info!("InboundRouter shutting down (incoming streams closed)");
        });

        InboundRouterHandle { join_handle }
    }

    /// Handle a single incoming stream.
    async fn handle_stream(&self, _peer: PeerId, mut stream: Stream) -> Result<(), StreamError> {
        // Read length-prefixed compressed request with timeout
        let compressed_request = tokio::time::timeout(STREAM_IO_TIMEOUT, async {
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await?;
            let len = u32::from_be_bytes(len_bytes) as usize;

            if len > MAX_REQUEST_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "request too large",
                ));
            }

            let mut data = vec![0u8; len];
            stream.read_exact(&mut data).await?;
            Ok::<Vec<u8>, std::io::Error>(data)
        })
        .await
        .map_err(|_| StreamError::Timeout)?
        .map_err(StreamError::Io)?;

        // Decompress request
        let request_data = wire::decompress(&compressed_request).map_err(|e| {
            StreamError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decompression failed: {}", e),
            ))
        })?;

        // Delegate to handler for request processing
        let response_sbor = self.handler.handle_request(&request_data);

        // Compress response
        let response_data = wire::compress(&response_sbor);

        // Write length-prefixed compressed response with timeout
        tokio::time::timeout(STREAM_IO_TIMEOUT, async {
            let len = response_data.len() as u32;
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(&response_data).await?;
            stream.flush().await?;
            stream.close().await?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(|_| StreamError::Timeout)?
        .map_err(StreamError::Io)?;

        Ok(())
    }
}

/// Spawn an inbound router with the given handler.
///
/// Used internally by `ProdNetwork::register_inbound_handler`.
pub(crate) fn spawn_inbound_router<H: InboundRequestHandler>(
    adapter: Arc<Libp2pAdapter>,
    handler: H,
) -> InboundRouterHandle {
    InboundRouter::spawn(adapter, handler)
}

/// Errors that can occur during stream handling.
#[derive(Debug)]
enum StreamError {
    Timeout,
    Io(std::io::Error),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Timeout => write!(f, "stream timeout"),
            StreamError::Io(e) => write!(f, "stream I/O error: {}", e),
        }
    }
}
