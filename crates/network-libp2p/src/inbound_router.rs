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
//! │                         InboundRouter<S>                                   │
//! │                                                                            │
//! │  Transport: read/write length-prefixed, compressed streams                │
//! │  Logic:     delegates to InboundHandler<S> from hyperscale-network        │
//! │                                                                            │
//! └────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Design Goals
//!
//! 1. **Separation of Concerns**: Transport handles framing/compression, `InboundHandler` handles request logic
//! 2. **Request-Response via Streams**: Uses raw libp2p streams with length-prefixed framing
//! 3. **Generic over Storage**: Parameterized over `ConsensusStore`, no concrete storage dependency

use crate::adapter::{Libp2pAdapter, STREAM_PROTOCOL};
use crate::inbound::{InboundHandler, InboundHandlerConfig};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use hyperscale_network::wire;
use hyperscale_storage::ConsensusStore;
use hyperscale_types::{Hash, RoutableTransaction, TransactionCertificate};
use libp2p::{PeerId, Stream};
use quick_cache::sync::Cache as QuickCache;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Timeout for reading requests and writing responses on streams.
const STREAM_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum request size (10MB).
const MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024;

/// Configuration for the inbound router.
pub type InboundRouterConfig = InboundHandlerConfig;

/// Handle for the inbound router task.
pub struct InboundRouterHandle {
    join_handle: tokio::task::JoinHandle<()>,
}

impl InboundRouterHandle {
    /// Check if the router task is still running.
    pub fn is_running(&self) -> bool {
        !self.join_handle.is_finished()
    }

    /// Wait for the router task to complete.
    pub async fn wait(self) {
        let _ = self.join_handle.await;
    }
}

/// Routes inbound requests to appropriate handlers.
///
/// The router accepts incoming streams and for each:
/// 1. Reads the length-prefixed compressed request
/// 2. Decompresses and delegates to `InboundHandler<S>` for processing
/// 3. Compresses and writes the length-prefixed response
/// 4. Closes the stream
///
/// Generic over `S: ConsensusStore` — the concrete storage type is supplied
/// by the production runner when constructing the router.
pub struct InboundRouter<S: ConsensusStore> {
    handler: InboundHandler<S>,
}

impl<S: ConsensusStore + 'static> InboundRouter<S> {
    /// Create a new inbound router.
    pub fn new(
        config: InboundRouterConfig,
        storage: Arc<S>,
        recently_received_txs: Arc<QuickCache<Hash, Arc<RoutableTransaction>>>,
        recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
    ) -> Self {
        Self {
            handler: InboundHandler::new(
                config,
                storage,
                recently_received_txs,
                recently_built_certs,
            ),
        }
    }

    /// Spawn the inbound router as a background task.
    ///
    /// The router will accept incoming streams until the stream control is dropped.
    pub fn spawn(
        config: InboundRouterConfig,
        adapter: Arc<Libp2pAdapter>,
        storage: Arc<S>,
        recently_received_txs: Arc<QuickCache<Hash, Arc<RoutableTransaction>>>,
        recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
    ) -> InboundRouterHandle {
        let join_handle = tokio::spawn(async move {
            let router = Arc::new(Self::new(
                config,
                storage,
                recently_received_txs,
                recently_built_certs,
            ));
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
    async fn handle_stream(&self, peer: PeerId, mut stream: Stream) -> Result<(), StreamError> {
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

        // Delegate to InboundHandler for request processing
        let response_sbor = match self.handler.process_request(&request_data) {
            Ok(data) => data,
            Err(e) => {
                debug!(peer = %peer, error = %e, "Request processing failed");
                vec![]
            }
        };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = InboundRouterConfig::default();
        assert_eq!(config.max_items_per_response, 500);
    }
}
