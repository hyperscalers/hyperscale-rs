//! Routes inbound network requests to appropriate handlers.
//!
//! This component accepts incoming streams from peers and routes them to the
//! appropriate handler based on request type. It unifies the handling of:
//! - Block sync requests
//! - Transaction fetch requests
//! - Certificate fetch requests

use crate::adapter::{Libp2pAdapter, STREAM_PROTOCOL};
use crate::framing::{self, FrameError, MAX_FRAME_SIZE};
use futures::StreamExt;
use hyperscale_network::InboundRequestHandler;
use libp2p::{PeerId, Stream};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Timeout for reading requests and writing responses on streams.
const STREAM_IO_TIMEOUT: Duration = Duration::from_secs(5);

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
        let request_data = tokio::time::timeout(
            STREAM_IO_TIMEOUT,
            framing::read_frame(&mut stream, MAX_FRAME_SIZE),
        )
        .await
        .map_err(|_| StreamError::Timeout)?
        .map_err(StreamError::Frame)?;

        // Delegate to handler for request processing
        let response_sbor = self.handler.handle_request(&request_data);

        // Write length-prefixed compressed response with timeout
        tokio::time::timeout(
            STREAM_IO_TIMEOUT,
            framing::write_frame(&mut stream, &response_sbor),
        )
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
    Frame(FrameError),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Timeout => write!(f, "stream timeout"),
            StreamError::Io(e) => write!(f, "stream I/O error: {}", e),
            StreamError::Frame(e) => write!(f, "stream frame error: {}", e),
        }
    }
}
