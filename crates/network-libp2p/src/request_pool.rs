//! Persistent per-peer request/response stream pool.
//!
//! `libp2p-stream` serializes outbound stream opens through a single
//! `pending_upgrade` slot per connection handler. Opening a fresh stream per
//! request (as the old `RequestManager` did) overwhelms that slot and causes
//! every open to time out. This module maintains one long-lived request stream
//! per peer and multiplexes sequential request/response pairs over it, so
//! `open_stream` is called at most once per peer per reconnect.
//!
//! Each peer gets a dedicated tokio actor that owns the `Stream` and receives
//! `PendingRequest` messages via an `mpsc` channel. Because responses are read
//! in the order requests are written, we don't need request IDs — the stream
//! itself is the ordering primitive.
//!
//! On any I/O error or per-request timeout, the actor tears down the stream
//! and exits. The next `send()` call detects the dead channel and spawns a
//! fresh actor (subject to exponential backoff).

use crate::adapter::{Libp2pAdapter, NetworkError};
use crate::stream_framing::{self, MAX_FRAME_SIZE};
use dashmap::DashMap;
use futures::AsyncReadExt;
use hyperscale_metrics as metrics;
use hyperscale_network::compression;
use libp2p::{PeerId, Stream};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

/// Initial reconnection backoff after a stream failure.
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Maximum reconnection backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Backoff multiplier for exponential backoff.
const BACKOFF_MULTIPLIER: u32 = 2;

/// Channel capacity per peer. Bounds memory and provides caller backpressure.
const PEER_CHANNEL_CAPACITY: usize = 64;

/// A request queued for dispatch on a peer's persistent stream.
struct PendingRequest {
    type_id: &'static str,
    data: Vec<u8>,
    /// Per-request I/O timeout. Covers write + response read on the stream.
    /// On timeout the actor tears down the stream (state unknowable).
    timeout: Duration,
    resp_tx: oneshot::Sender<Result<Vec<u8>, NetworkError>>,
}

/// Exponential backoff state for a peer after stream failure.
struct BackoffState {
    next_attempt: Instant,
    current_backoff: Duration,
}

/// Handle to a per-peer request actor. Dropping the sender closes the channel,
/// which causes the actor to drain remaining requests and shut down.
struct PeerRequestActor {
    req_tx: mpsc::Sender<PendingRequest>,
}

/// Manages persistent outbound request streams, one per peer.
pub struct RequestStreamPool {
    adapter: Arc<Libp2pAdapter>,
    peers: Arc<DashMap<PeerId, PeerRequestActor>>,
    backoff: Arc<DashMap<PeerId, BackoffState>>,
    tokio_handle: tokio::runtime::Handle,
}

impl RequestStreamPool {
    pub fn new(adapter: Arc<Libp2pAdapter>, tokio_handle: tokio::runtime::Handle) -> Self {
        Self {
            adapter,
            peers: Arc::new(DashMap::new()),
            backoff: Arc::new(DashMap::new()),
            tokio_handle,
        }
    }

    /// Send a request to `peer` and await the response.
    ///
    /// `timeout` bounds the I/O for this request once the actor picks it up —
    /// it does not bound queueing delay behind other pending requests on the
    /// same peer (peer rotation at the request-manager layer handles that).
    pub async fn send(
        &self,
        peer: PeerId,
        type_id: &'static str,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>, NetworkError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let req = PendingRequest {
            type_id,
            data,
            timeout,
            resp_tx,
        };

        self.dispatch(peer, req).await?;

        match resp_rx.await {
            Ok(result) => result,
            Err(_) => Err(NetworkError::StreamIo(
                "request actor dropped response channel".into(),
            )),
        }
    }

    /// Route a request to a live actor, spawning one if necessary.
    async fn dispatch(&self, peer: PeerId, req: PendingRequest) -> Result<(), NetworkError> {
        if let Some(actor) = self.peers.get(&peer) {
            let tx = actor.req_tx.clone();
            drop(actor);
            match tx.send(req).await {
                Ok(()) => return Ok(()),
                Err(mpsc::error::SendError(returned)) => {
                    // Actor task is dead. Remove and fall through to spawn.
                    self.peers.remove(&peer);
                    return self.spawn_and_send(peer, returned).await;
                }
            }
        }

        self.spawn_and_send(peer, req).await
    }

    /// Spawn a new actor for `peer` (respecting backoff) and enqueue `req`.
    async fn spawn_and_send(&self, peer: PeerId, req: PendingRequest) -> Result<(), NetworkError> {
        if let Some(state) = self.backoff.get(&peer) {
            if Instant::now() < state.next_attempt {
                return Err(NetworkError::StreamIo(
                    "peer in backoff after recent failure".into(),
                ));
            }
        }

        let (req_tx, req_rx) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        if req_tx.send(req).await.is_err() {
            // Shouldn't happen — we just created the channel.
            return Err(NetworkError::StreamIo("failed to enqueue request".into()));
        }

        self.peers.insert(peer, PeerRequestActor { req_tx });

        let peers = self.peers.clone();
        let backoff = self.backoff.clone();
        let adapter = self.adapter.clone();

        self.tokio_handle.spawn(async move {
            Self::run_actor(peer, req_rx, adapter, peers, backoff).await;
        });

        Ok(())
    }

    /// Actor task: opens a persistent stream and services queued requests
    /// in order. Exits (and tears down the stream) on any I/O error or
    /// request timeout.
    async fn run_actor(
        peer: PeerId,
        mut req_rx: mpsc::Receiver<PendingRequest>,
        adapter: Arc<Libp2pAdapter>,
        peers: Arc<DashMap<PeerId, PeerRequestActor>>,
        backoff_map: Arc<DashMap<PeerId, BackoffState>>,
    ) {
        let mut stream = match adapter.open_request_stream(peer).await {
            Ok(s) => s,
            Err(e) => {
                warn!(peer = %peer, error = ?e, "Failed to open persistent request stream");
                // Fail every pending request so callers see the error promptly.
                drain_with_error(&mut req_rx, || {
                    NetworkError::StreamOpenFailed(format!("{e:?}"))
                });
                Self::apply_backoff(&backoff_map, &peer);
                peers.remove(&peer);
                return;
            }
        };

        backoff_map.remove(&peer);

        while let Some(req) = req_rx.recv().await {
            let io = tokio::time::timeout(
                req.timeout,
                do_request_response(&mut stream, req.type_id, &req.data),
            )
            .await;

            match io {
                Ok(Ok(response)) => {
                    let _ = req.resp_tx.send(Ok(response));
                }
                Ok(Err(e)) => {
                    let msg = format!("{e:?}");
                    let _ = req.resp_tx.send(Err(e));
                    warn!(peer = %peer, error = %msg, "Persistent request stream I/O failed");
                    drain_with_error(&mut req_rx, || {
                        NetworkError::StreamIo("peer stream reset after prior failure".into())
                    });
                    Self::apply_backoff(&backoff_map, &peer);
                    break;
                }
                Err(_) => {
                    let _ = req.resp_tx.send(Err(NetworkError::Timeout));
                    // Timeout means the response (if any) is unread on the
                    // wire. Tear down to avoid stale-response reads.
                    drain_with_error(&mut req_rx, || {
                        NetworkError::StreamIo("peer stream reset after request timeout".into())
                    });
                    Self::apply_backoff(&backoff_map, &peer);
                    break;
                }
            }
        }

        peers.remove(&peer);
    }

    fn apply_backoff(backoff_map: &DashMap<PeerId, BackoffState>, peer: &PeerId) {
        let current_backoff = backoff_map
            .get(peer)
            .map(|state| (state.current_backoff * BACKOFF_MULTIPLIER).min(MAX_BACKOFF))
            .unwrap_or(INITIAL_BACKOFF);

        backoff_map.insert(
            *peer,
            BackoffState {
                next_attempt: Instant::now() + current_backoff,
                current_backoff,
            },
        );
    }
}

/// Write a typed request frame and read the length-prefixed response.
async fn do_request_response(
    stream: &mut Stream,
    type_id: &str,
    data: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    let wire_bytes = stream_framing::write_typed_frame(stream, type_id, data)
        .await
        .map_err(|e| NetworkError::StreamIo(format!("write failed: {e}")))?;
    metrics::record_libp2p_bandwidth(0, wire_bytes as u64);

    let response_len = stream_framing::read_frame_len(stream, MAX_FRAME_SIZE)
        .await
        .map_err(|e| NetworkError::StreamIo(format!("read length failed: {e}")))?;

    let mut compressed = vec![0u8; response_len];
    stream
        .read_exact(&mut compressed)
        .await
        .map_err(|e| NetworkError::StreamIo(format!("read body failed: {e}")))?;

    metrics::record_libp2p_bandwidth((4 + response_len) as u64, 0);

    compression::decompress(&compressed)
        .map_err(|e| NetworkError::StreamIo(format!("decompression failed: {e}")))
}

/// Drain any remaining queued requests and fail them with a fresh error
/// constructed from `err_fn`. Called after a stream tear-down so pending
/// callers don't wait forever for a response that will never arrive.
fn drain_with_error(
    req_rx: &mut mpsc::Receiver<PendingRequest>,
    err_fn: impl Fn() -> NetworkError,
) {
    while let Ok(req) = req_rx.try_recv() {
        let _ = req.resp_tx.send(Err(err_fn()));
    }
}
