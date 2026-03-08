//! Routes inbound network requests to per-type handlers.
//!
//! This component accepts incoming streams from peers and dispatches them to
//! the appropriate handler based on the request type_id in the frame header.
//! The handler registry is populated during node initialization.
//!
//! Concurrency is bounded by a global semaphore and per-peer counters to
//! prevent any single peer (or flood of peers) from exhausting handler capacity.

use crate::adapter::{Libp2pAdapter, NOTIFY_PROTOCOL, REQUEST_PROTOCOL};
use crate::stream_framing::{self, FrameError, MAX_FRAME_SIZE};
use dashmap::DashMap;
use futures::{AsyncWriteExt, StreamExt};
use hyperscale_metrics as metrics;
use hyperscale_network::HandlerRegistry;
use libp2p::{PeerId, Stream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::debug;

/// Timeout for reading requests and writing responses on streams.
const STREAM_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Idle timeout for persistent notification streams.
///
/// If no frame is received within this period, the stream is closed.
/// The sender will detect the write error and reconnect when it has
/// more frames to send. Longer than QUIC idle timeout (30s) so QUIC
/// keep-alive handles liveness detection; this just prevents resource
/// leaks if a sender silently disappears.
const PERSISTENT_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of inbound streams handled concurrently across all peers.
const MAX_INBOUND_CONCURRENT: usize = 128;

/// Maximum number of concurrent inbound streams from a single peer.
const MAX_INBOUND_PER_PEER: usize = 16;

/// Handle for the inbound router tasks.
///
/// Kept alive inside `Libp2pNetwork` to prevent the tokio tasks from being
/// aborted when the `JoinHandle`s are dropped.
pub(crate) struct InboundRouterHandle {
    #[allow(dead_code)]
    request_handle: tokio::task::JoinHandle<()>,
    #[allow(dead_code)]
    notify_handle: tokio::task::JoinHandle<()>,
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
    /// Spawn the inbound router as two background tasks (request + notification).
    ///
    /// The router will accept incoming streams until the stream control is dropped.
    fn spawn(adapter: Arc<Libp2pAdapter>, registry: Arc<HandlerRegistry>) -> InboundRouterHandle {
        let router = Arc::new(InboundRouter {
            registry,
            global_semaphore: Arc::new(Semaphore::new(MAX_INBOUND_CONCURRENT)),
            per_peer: Arc::new(DashMap::new()),
        });

        // ── Request accept loop (REQUEST_PROTOCOL) ──
        let request_handle = {
            let router = router.clone();
            let mut control = adapter.stream_control();
            tokio::spawn(async move {
                let mut incoming = match control.accept(REQUEST_PROTOCOL) {
                    Ok(incoming) => incoming,
                    Err(e) => {
                        tracing::error!(error = ?e, "Failed to register request protocol");
                        return;
                    }
                };

                tracing::info!("InboundRouter: request loop started");

                while let Some((peer_id, stream)) = incoming.next().await {
                    if let Some(permit) = router.try_admit(&peer_id) {
                        let router_clone = router.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            let result = router_clone.handle_request_stream(peer_id, stream).await;
                            router_clone.decrement_peer_count(&peer_id);
                            if let Err(e) = result {
                                debug!(peer = %peer_id, error = ?e, "Request stream handling failed");
                            }
                        });
                    } else {
                        drop(stream);
                    }
                }

                tracing::info!("InboundRouter: request loop shutting down");
            })
        };

        // ── Notification accept loop (NOTIFY_PROTOCOL) ──
        let notify_handle = {
            let router = router.clone();
            let mut control = adapter.stream_control();
            tokio::spawn(async move {
                let mut incoming = match control.accept(NOTIFY_PROTOCOL) {
                    Ok(incoming) => incoming,
                    Err(e) => {
                        tracing::error!(error = ?e, "Failed to register notify protocol");
                        return;
                    }
                };

                tracing::info!("InboundRouter: notification loop started");

                while let Some((peer_id, stream)) = incoming.next().await {
                    if let Some(permit) = router.try_admit(&peer_id) {
                        let router_clone = router.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            let result = router_clone
                                .handle_notification_stream(peer_id, stream)
                                .await;
                            router_clone.decrement_peer_count(&peer_id);
                            if let Err(e) = result {
                                debug!(peer = %peer_id, error = ?e, "Notification stream handling failed");
                            }
                        });
                    } else {
                        drop(stream);
                    }
                }

                tracing::info!("InboundRouter: notification loop shutting down");
            })
        };

        InboundRouterHandle {
            request_handle,
            notify_handle,
        }
    }

    /// Try to admit an inbound stream, checking per-peer and global limits.
    ///
    /// Returns `Some(permit)` if admitted, `None` if rejected.
    fn try_admit(self: &Arc<Self>, peer_id: &PeerId) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let peer_counter = self
            .per_peer
            .entry(*peer_id)
            .or_insert_with(|| AtomicUsize::new(0));
        let prev = peer_counter.fetch_add(1, Ordering::Relaxed);
        drop(peer_counter);
        if prev >= MAX_INBOUND_PER_PEER {
            self.decrement_peer_count(peer_id);
            debug!(
                peer = %peer_id,
                active = prev,
                limit = MAX_INBOUND_PER_PEER,
                "Dropping inbound stream: per-peer limit exceeded"
            );
            return None;
        }

        match self.global_semaphore.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                self.decrement_peer_count(peer_id);
                debug!(
                    peer = %peer_id,
                    limit = MAX_INBOUND_CONCURRENT,
                    "Dropping inbound stream: global concurrency limit reached"
                );
                None
            }
        }
    }

    /// Decrement the per-peer active stream counter.
    fn decrement_peer_count(&self, peer_id: &PeerId) {
        if let Some(counter) = self.per_peer.get(peer_id) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Handle a single incoming request stream (read request, call handler, write response).
    async fn handle_request_stream(
        &self,
        _peer: PeerId,
        mut stream: Stream,
    ) -> Result<(), StreamError> {
        // Read typed frame: type_id header + compressed SBOR payload.
        let (type_id, sbor_payload, req_wire_bytes) = tokio::time::timeout(
            STREAM_IO_TIMEOUT,
            stream_framing::read_typed_frame(&mut stream, MAX_FRAME_SIZE),
        )
        .await
        .map_err(|_| StreamError::Timeout)?
        .map_err(StreamError::Frame)?;

        metrics::record_libp2p_bandwidth(req_wire_bytes as u64, 0);

        // Look up the per-type request handler.
        let handler = self
            .registry
            .get_request(&type_id)
            .ok_or(StreamError::UnknownMessageType)?;

        // Delegate to the handler (receives raw SBOR payload, returns SBOR response).
        let response_sbor = handler(&sbor_payload);

        // Write length-prefixed compressed response with timeout.
        let resp_wire_bytes = tokio::time::timeout(
            STREAM_IO_TIMEOUT,
            stream_framing::write_frame(&mut stream, &response_sbor),
        )
        .await
        .map_err(|_| StreamError::Timeout)?
        .map_err(StreamError::Io)?;

        metrics::record_libp2p_bandwidth(0, resp_wire_bytes as u64);

        Ok(())
    }

    /// Handle a persistent incoming notification stream.
    ///
    /// Reads typed frames in a loop until the stream is closed by the sender,
    /// an error occurs, or the idle timeout elapses. Each frame is dispatched
    /// to the registered handler.
    async fn handle_notification_stream(
        &self,
        peer: PeerId,
        mut stream: Stream,
    ) -> Result<(), StreamError> {
        loop {
            let read_result = tokio::time::timeout(
                PERSISTENT_STREAM_IDLE_TIMEOUT,
                stream_framing::read_typed_frame(&mut stream, MAX_FRAME_SIZE),
            )
            .await;

            let (type_id, sbor_payload, wire_bytes) = match read_result {
                Ok(Ok(frame)) => frame,
                Ok(Err(FrameError::Io(ref e))) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Clean stream closure by sender.
                    debug!(peer = %peer, "Notification stream closed by sender");
                    return Ok(());
                }
                Ok(Err(e)) => {
                    return Err(StreamError::Frame(e));
                }
                Err(_) => {
                    // Idle timeout — close our side. The sender will get a
                    // write error and reconnect when it has more frames.
                    debug!(peer = %peer, "Notification stream idle timeout, closing");
                    let _ = stream.close().await;
                    return Ok(());
                }
            };

            metrics::record_libp2p_bandwidth(wire_bytes as u64, 0);

            // Look up the per-type notification handler.
            if let Some(handler) = self.registry.get_notification(&type_id) {
                tokio::spawn(async move { handler(sbor_payload) });
            } else {
                debug!(
                    peer = %peer,
                    type_id = %type_id,
                    "Unknown notification type on persistent stream"
                );
                // Don't close — the sender may send other known types.
            }
        }
    }
}

/// Spawn an inbound router with the given handler registry.
///
/// Used internally by `Libp2pNetwork`.
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
    UnknownMessageType,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Timeout => write!(f, "stream timeout"),
            StreamError::Io(e) => write!(f, "stream I/O error: {}", e),
            StreamError::Frame(e) => write!(f, "stream frame error: {}", e),
            StreamError::UnknownMessageType => write!(f, "unknown message type"),
        }
    }
}
