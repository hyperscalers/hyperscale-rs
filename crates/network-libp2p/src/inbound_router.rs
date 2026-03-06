//! Routes inbound network requests to per-type handlers.
//!
//! This component accepts incoming streams from peers and dispatches them to
//! the appropriate handler based on the request type_id in the frame header.
//! The handler registry is populated during node initialization.
//!
//! Concurrency is bounded by a global semaphore and per-peer counters to
//! prevent any single peer (or flood of peers) from exhausting handler capacity.

use crate::adapter::{Libp2pAdapter, STREAM_PROTOCOL};
use crate::stream_framing::{self, FrameError, MAX_FRAME_SIZE};
use dashmap::DashMap;
use futures::StreamExt;
use hyperscale_network::HandlerRegistry;
use libp2p::{PeerId, Stream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::debug;

/// Timeout for reading requests and writing responses on streams.
const STREAM_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of inbound streams handled concurrently across all peers.
const MAX_INBOUND_CONCURRENT: usize = 128;

/// Maximum number of concurrent inbound streams from a single peer.
const MAX_INBOUND_PER_PEER: usize = 16;

/// Handle for the inbound router task.
///
/// Kept alive inside `ProdNetwork` to prevent the tokio task from being
/// aborted when the `JoinHandle` is dropped.
pub(crate) struct InboundRouterHandle {
    #[allow(dead_code)]
    join_handle: tokio::task::JoinHandle<()>,
}

/// Routes inbound requests to per-type handlers via the handler registry.
///
/// The router accepts incoming streams and for each:
/// 1. Checks per-peer and global concurrency limits
/// 2. Reads the typed frame header (type_id) + compressed SBOR payload
/// 3. Looks up the handler in the registry and calls it with the SBOR payload
/// 4. Compresses and writes the length-prefixed response
/// 5. Closes the stream
struct InboundRouter {
    registry: Arc<HandlerRegistry>,
    /// Global concurrency limiter. Each active stream holds one permit.
    global_semaphore: Arc<Semaphore>,
    /// Per-peer active stream count.
    per_peer: Arc<DashMap<PeerId, AtomicUsize>>,
}

impl InboundRouter {
    /// Spawn the inbound router as a background task.
    ///
    /// The router will accept incoming streams until the stream control is dropped.
    fn spawn(adapter: Arc<Libp2pAdapter>, registry: Arc<HandlerRegistry>) -> InboundRouterHandle {
        let join_handle = tokio::spawn(async move {
            let router = Arc::new(InboundRouter {
                registry,
                global_semaphore: Arc::new(Semaphore::new(MAX_INBOUND_CONCURRENT)),
                per_peer: Arc::new(DashMap::new()),
            });
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

            // Accept incoming streams with concurrency control
            while let Some((peer_id, stream)) = incoming.next().await {
                // Per-peer check (fast path, no async wait).
                let peer_counter = router
                    .per_peer
                    .entry(peer_id)
                    .or_insert_with(|| AtomicUsize::new(0));
                let prev = peer_counter.fetch_add(1, Ordering::Relaxed);
                drop(peer_counter); // release DashMap shard lock
                if prev >= MAX_INBOUND_PER_PEER {
                    router.decrement_peer_count(&peer_id);
                    debug!(
                        peer = %peer_id,
                        active = prev,
                        limit = MAX_INBOUND_PER_PEER,
                        "Dropping inbound stream: per-peer limit exceeded"
                    );
                    drop(stream);
                    continue;
                }

                // Global concurrency: try_acquire (non-blocking).
                // Under overload we drop rather than queue — the remote side retries.
                let permit = match router.global_semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        router.decrement_peer_count(&peer_id);
                        debug!(
                            peer = %peer_id,
                            limit = MAX_INBOUND_CONCURRENT,
                            "Dropping inbound stream: global concurrency limit reached"
                        );
                        drop(stream);
                        continue;
                    }
                };

                let router_clone = router.clone();

                // Spawn a task to handle the stream. The semaphore permit is
                // moved in and auto-dropped when the task completes.
                tokio::spawn(async move {
                    let _permit = permit;
                    let result = router_clone.handle_stream(peer_id, stream).await;
                    router_clone.decrement_peer_count(&peer_id);

                    if let Err(e) = result {
                        debug!(peer = %peer_id, error = ?e, "Stream handling failed");
                    }
                });
            }

            tracing::info!("InboundRouter shutting down (incoming streams closed)");
        });

        InboundRouterHandle { join_handle }
    }

    /// Decrement the per-peer active stream counter.
    fn decrement_peer_count(&self, peer_id: &PeerId) {
        if let Some(counter) = self.per_peer.get(peer_id) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Handle a single incoming stream.
    async fn handle_stream(&self, _peer: PeerId, mut stream: Stream) -> Result<(), StreamError> {
        // Read typed frame: type_id header + compressed SBOR payload.
        // The type_id is outside the compressed payload for routing without decompression.
        let (type_id, sbor_payload) = tokio::time::timeout(
            STREAM_IO_TIMEOUT,
            stream_framing::read_typed_frame(&mut stream, MAX_FRAME_SIZE),
        )
        .await
        .map_err(|_| StreamError::Timeout)?
        .map_err(StreamError::Frame)?;

        // Look up the per-type request handler.
        let handler = self
            .registry
            .get_request(&type_id)
            .ok_or(StreamError::UnknownRequestType)?;

        // Delegate to the handler (receives raw SBOR payload, returns SBOR response).
        let response_sbor = handler(&sbor_payload);

        // Write length-prefixed compressed response with timeout
        tokio::time::timeout(
            STREAM_IO_TIMEOUT,
            stream_framing::write_frame(&mut stream, &response_sbor),
        )
        .await
        .map_err(|_| StreamError::Timeout)?
        .map_err(StreamError::Io)?;

        Ok(())
    }
}

/// Spawn an inbound router with the given handler registry.
///
/// Used internally by `ProdNetwork`.
pub(crate) fn spawn_inbound_router(
    adapter: Arc<Libp2pAdapter>,
    registry: Arc<HandlerRegistry>,
) -> InboundRouterHandle {
    InboundRouter::spawn(adapter, registry)
}

/// Errors that can occur during stream handling.
#[derive(Debug)]
enum StreamError {
    Timeout,
    Io(std::io::Error),
    Frame(FrameError),
    UnknownRequestType,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Timeout => write!(f, "stream timeout"),
            StreamError::Io(e) => write!(f, "stream I/O error: {}", e),
            StreamError::Frame(e) => write!(f, "stream frame error: {}", e),
            StreamError::UnknownRequestType => write!(f, "unknown request type"),
        }
    }
}
