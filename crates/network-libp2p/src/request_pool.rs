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
//! ## Stale-stream recovery
//!
//! The inbound router closes its side of an idle request stream after
//! `PERSISTENT_STREAM_IDLE_TIMEOUT` (60s). When we next write on a stream the
//! peer has already closed, the write returns a `StreamIo` error — harmless
//! but indistinguishable at the byte layer from a real fault. Because the
//! request never reached the peer, it's safe to reopen the stream and retry
//! the same request on the new stream. We close proactively after
//! `CLIENT_IDLE_TIMEOUT` (below the server timeout) to avoid the race in the
//! first place, and only fall back to the tear-down + backoff path after the
//! reopened stream also fails.
//!
//! On a response-phase error (read or decompression), the request already
//! crossed the wire so retry is not safe — the actor tears down and exits.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite};
use hyperscale_metrics::record_libp2p_bandwidth;
use hyperscale_network::compression::decompress;
use hyperscale_network::fault::Tier;
use hyperscale_types::ShardId;
use libp2p::PeerId;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, timeout as tokio_timeout};
use tracing::{debug, warn};

use crate::adapter::{Libp2pAdapter, NetworkError};
use crate::peer_backoff::{self, BackoffState};
use crate::stream_framing::{self, MAX_FRAME_SIZE};

/// Channel capacity per peer. Bounds memory and provides caller backpressure.
const PEER_CHANNEL_CAPACITY: usize = 64;

/// Abstraction over a per-peer request/response pool.
///
/// Lets [`RequestManager`] swap in a deterministic mock for retry-loop tests
/// without standing up a real libp2p stack. The trait is object-safe (no
/// generic methods, no `Self` returns), so the manager holds it as a
/// trait object — `Arc<RequestStreamPool>` coerces to `Arc<dyn RequestPool>`
/// automatically at construction sites.
///
/// [`RequestManager`]: crate::RequestManager
pub trait RequestPool: Send + Sync + 'static {
    /// Send a request to `peer` over `shard`'s request protocol and await
    /// the response.
    ///
    /// `timeout` bounds the I/O for this request once the pool dispatches
    /// it. The future is boxed because the trait is object-safe; the
    /// `'a` lifetime lets implementations borrow from `&self`.
    fn send<'a>(
        &'a self,
        peer: PeerId,
        shard: ShardId,
        type_id: &'static str,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, NetworkError>> + Send + 'a>>;

    /// Whether `(peer, shard)`'s stream is currently in reconnection backoff —
    /// a recent failure whose cooldown has not elapsed. The request manager
    /// consults this so peer selection skips a peer that would only instant-fail
    /// (and re-escalate its backoff), and surfaces `NoPeers` when every
    /// candidate is backed off rather than spinning. Defaults to `false` for
    /// pools without a backoff layer (test doubles, the notify path).
    fn is_backed_off(&self, _peer: PeerId, _shard: ShardId) -> bool {
        false
    }
}

impl RequestPool for RequestStreamPool {
    fn send<'a>(
        &'a self,
        peer: PeerId,
        shard: ShardId,
        type_id: &'static str,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, NetworkError>> + Send + 'a>> {
        Box::pin(Self::send(self, peer, shard, type_id, data, timeout))
    }

    fn is_backed_off(&self, peer: PeerId, shard: ShardId) -> bool {
        self.backoff
            .get(&(peer, shard))
            .is_some_and(|state| Instant::now() < state.next_attempt)
    }
}

/// Proactively close the persistent stream after this long without new
/// requests. Must be strictly less than the inbound router's
/// `PERSISTENT_STREAM_IDLE_TIMEOUT` so we always close before the peer does,
/// avoiding the "write failed: sending stopped by peer" race on the next
/// request after an idle gap.
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(45);

/// A request queued for dispatch on a peer's persistent stream.
struct PendingRequest {
    type_id: &'static str,
    data: Vec<u8>,
    /// Per-request I/O timeout. Covers write + response read on the stream.
    /// On timeout the actor tears down the stream (state unknowable).
    timeout: Duration,
    resp_tx: oneshot::Sender<Result<Vec<u8>, NetworkError>>,
}

/// Handle to a per-peer request actor. Dropping the sender closes the channel,
/// which causes the actor to drain remaining requests and shut down.
struct PeerRequestActor {
    req_tx: mpsc::Sender<PendingRequest>,
}

/// Per-actor key: one persistent stream per `(peer, shard)` pair. With
/// V=1 single-shard hosting this collapses to one entry per peer; under
/// multi-shard hosting the key grows with hosted-shard cardinality.
type ActorKey = (PeerId, ShardId);

/// Manages persistent outbound request streams, one per `(peer, shard)` pair.
pub struct RequestStreamPool {
    adapter: Arc<Libp2pAdapter>,
    peers: Arc<DashMap<ActorKey, PeerRequestActor>>,
    backoff: Arc<DashMap<ActorKey, BackoffState>>,
    tokio_handle: Handle,
    /// Per-request outbound delay (`Duration::ZERO` in production).
    latency: Duration,
}

impl RequestStreamPool {
    /// Build an empty pool that lazily spawns one per-(peer,shard) request
    /// actor on demand.
    #[must_use]
    pub fn new(adapter: Arc<Libp2pAdapter>, tokio_handle: Handle, latency: Duration) -> Self {
        Self {
            adapter,
            peers: Arc::new(DashMap::new()),
            backoff: Arc::new(DashMap::new()),
            tokio_handle,
            latency,
        }
    }

    /// Send a request to `peer` over `shard`'s request protocol and await
    /// the response.
    ///
    /// `timeout` bounds the I/O for this request once the actor picks it up —
    /// it does not bound queueing delay behind other pending requests on the
    /// same `(peer, shard)` actor (peer rotation at the request-manager
    /// layer handles that).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`NetworkError`] if the per-(peer,shard)
    /// actor cannot be spawned, the stream open fails, or the request
    /// times out.
    pub async fn send(
        &self,
        peer: PeerId,
        shard: ShardId,
        type_id: &'static str,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>, NetworkError> {
        // Fault gate: drop this request leg per attempt. A dropped leg never
        // reaches the peer, so it surfaces as a timeout — exactly what the retry
        // loop sees on real packet loss, and it re-rolls the gate on the next
        // attempt (the seeded probabilistic request drop).
        if self
            .adapter
            .fault_gate()
            .drop_outbound(peer, type_id, Tier::Request)
        {
            return Err(NetworkError::Timeout);
        }

        let (resp_tx, resp_rx) = oneshot::channel();
        let req = PendingRequest {
            type_id,
            data,
            timeout,
            resp_tx,
        };

        self.dispatch((peer, shard), req).await?;

        resp_rx.await.unwrap_or_else(|_| {
            Err(NetworkError::StreamIo(
                "request actor dropped response channel".into(),
            ))
        })
    }

    /// Route a request to a live actor, spawning one if necessary.
    async fn dispatch(&self, key: ActorKey, req: PendingRequest) -> Result<(), NetworkError> {
        if let Some(actor) = self.peers.get(&key) {
            let tx = actor.req_tx.clone();
            drop(actor);
            match tx.send(req).await {
                Ok(()) => return Ok(()),
                Err(mpsc::error::SendError(returned)) => {
                    // Actor task is dead. Remove and fall through to spawn.
                    self.peers.remove(&key);
                    return self.spawn_and_send(key, returned).await;
                }
            }
        }

        self.spawn_and_send(key, req).await
    }

    /// Spawn a new actor for `key` (respecting backoff) and enqueue `req`.
    async fn spawn_and_send(&self, key: ActorKey, req: PendingRequest) -> Result<(), NetworkError> {
        if let Some(state) = self.backoff.get(&key)
            && Instant::now() < state.next_attempt
        {
            return Err(NetworkError::StreamIo(
                "peer in backoff after recent failure".into(),
            ));
        }

        let (req_tx, req_rx) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        if req_tx.send(req).await.is_err() {
            // Shouldn't happen — we just created the channel.
            return Err(NetworkError::StreamIo("failed to enqueue request".into()));
        }

        self.peers.insert(key, PeerRequestActor { req_tx });

        let peers = self.peers.clone();
        let backoff = self.backoff.clone();
        let adapter = self.adapter.clone();
        let latency = self.latency;

        self.tokio_handle.spawn(async move {
            Self::run_actor(key, req_rx, adapter, peers, backoff, latency).await;
        });

        Ok(())
    }

    /// Actor task: opens a persistent stream and services queued requests
    /// in order. Closes cleanly after `CLIENT_IDLE_TIMEOUT` of inactivity.
    /// Tears down (and applies backoff) on a response-phase error or timeout.
    async fn run_actor(
        key: ActorKey,
        mut req_rx: mpsc::Receiver<PendingRequest>,
        adapter: Arc<Libp2pAdapter>,
        peers: Arc<DashMap<ActorKey, PeerRequestActor>>,
        backoff_map: Arc<DashMap<ActorKey, BackoffState>>,
        latency: Duration,
    ) {
        let (peer, shard) = key;
        let mut stream = match adapter.open_request_stream(peer, shard).await {
            Ok(s) => s,
            Err(e) => {
                warn!(peer = %peer, shard = shard.inner(), error = ?e, "Failed to open persistent request stream");
                // Fail every pending request so callers see the error promptly.
                drain_with_error(&mut req_rx, || {
                    NetworkError::StreamOpenFailed(format!("{e:?}"))
                });
                peer_backoff::apply_backoff(&backoff_map, &key);
                peers.remove(&key);
                return;
            }
        };

        backoff_map.remove(&key);

        loop {
            let req = tokio::select! {
                maybe_req = req_rx.recv() => match maybe_req {
                    Some(r) => r,
                    None => break,
                },
                () = sleep(CLIENT_IDLE_TIMEOUT) => {
                    debug!(peer = %peer, shard = shard.inner(), "Client idle timeout — closing persistent stream");
                    break;
                }
            };

            // Hold the request for the simulated one-way delay before it hits
            // the wire (test clusters only; `Duration::ZERO` in production).
            // Outside the per-request I/O timeout so it doesn't eat that budget.
            if !latency.is_zero() {
                sleep(latency).await;
            }

            let outcome = tokio_timeout(
                req.timeout,
                do_request_response(&mut stream, req.type_id, &req.data),
            )
            .await;

            // A write-phase failure usually means the peer closed the stream
            // between requests (inbound-router idle close). The request never
            // left our side, so reopen once and retry transparently before
            // tearing down.
            let outcome = match outcome {
                Ok(IoOutcome::WriteFailed(e)) => {
                    debug!(peer = %peer, shard = shard.inner(), error = ?e, "Write failed on persistent stream — reopening and retrying once");
                    match adapter.open_request_stream(peer, shard).await {
                        Ok(new_stream) => {
                            stream = new_stream;
                            tokio_timeout(
                                req.timeout,
                                do_request_response(&mut stream, req.type_id, &req.data),
                            )
                            .await
                        }
                        Err(reopen_err) => {
                            warn!(peer = %peer, shard = shard.inner(), error = ?reopen_err, "Failed to reopen persistent request stream");
                            Ok(IoOutcome::ResponseFailed(NetworkError::StreamOpenFailed(
                                format!("{reopen_err:?}"),
                            )))
                        }
                    }
                }
                other => other,
            };

            match outcome {
                Ok(IoOutcome::Ok(response)) => {
                    let _ = req.resp_tx.send(Ok(response));
                }
                Ok(IoOutcome::WriteFailed(e) | IoOutcome::ResponseFailed(e)) => {
                    let msg = format!("{e:?}");
                    let _ = req.resp_tx.send(Err(e));
                    warn!(peer = %peer, shard = shard.inner(), error = %msg, "Persistent request stream I/O failed");
                    drain_with_error(&mut req_rx, || {
                        NetworkError::StreamIo("peer stream reset after prior failure".into())
                    });
                    peer_backoff::apply_backoff(&backoff_map, &key);
                    peers.remove(&key);
                    return;
                }
                Err(_) => {
                    let _ = req.resp_tx.send(Err(NetworkError::Timeout));
                    // Timeout means the response (if any) is unread on the
                    // wire. Tear down to avoid stale-response reads.
                    drain_with_error(&mut req_rx, || {
                        NetworkError::StreamIo("peer stream reset after request timeout".into())
                    });
                    peer_backoff::apply_backoff(&backoff_map, &key);
                    peers.remove(&key);
                    return;
                }
            }
        }

        peers.remove(&key);
    }
}

/// Outcome of a single request/response round-trip on a persistent stream.
///
/// The distinction between `WriteFailed` and `ResponseFailed` drives the
/// stale-stream recovery: `WriteFailed` means the request never reached the
/// peer, so retrying on a fresh stream is safe. `ResponseFailed` means the
/// request was already on the wire — the peer may have processed it, so
/// retry could double-apply.
#[cfg_attr(test, derive(Debug))]
enum IoOutcome {
    Ok(Vec<u8>),
    WriteFailed(NetworkError),
    ResponseFailed(NetworkError),
}

/// Write a typed request frame and read the length-prefixed response.
async fn do_request_response<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    type_id: &str,
    data: &[u8],
) -> IoOutcome {
    let wire_bytes = match stream_framing::write_typed_frame(stream, type_id, data).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return IoOutcome::WriteFailed(NetworkError::StreamIo(format!("write failed: {e}")));
        }
    };
    record_libp2p_bandwidth(0, wire_bytes as u64);

    let response_len = match stream_framing::read_frame_len(stream, MAX_FRAME_SIZE).await {
        Ok(len) => len,
        Err(e) => {
            return IoOutcome::ResponseFailed(NetworkError::StreamIo(format!(
                "read length failed: {e}"
            )));
        }
    };

    let mut compressed = vec![0u8; response_len];
    if let Err(e) = stream.read_exact(&mut compressed).await {
        return IoOutcome::ResponseFailed(NetworkError::StreamIo(format!("read body failed: {e}")));
    }

    record_libp2p_bandwidth((4 + response_len) as u64, 0);

    match decompress(&compressed) {
        Ok(bytes) => IoOutcome::Ok(bytes),
        Err(e) => {
            IoOutcome::ResponseFailed(NetworkError::StreamIo(format!("decompression failed: {e}")))
        }
    }
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

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use futures::io::Cursor;
    use hyperscale_network::compression::compress;

    use super::*;
    use crate::stream_framing::read_typed_frame;

    /// In-memory bidirectional stream. Writes accumulate in `written`; reads
    /// drain from `to_read`. Optionally fails every write with a stub error.
    struct MockStream {
        written: Vec<u8>,
        to_read: Cursor<Vec<u8>>,
        write_err: Option<io::ErrorKind>,
    }

    impl MockStream {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                written: Vec::new(),
                to_read: Cursor::new(read_data),
                write_err: None,
            }
        }

        fn failing_writes(kind: io::ErrorKind) -> Self {
            Self {
                written: Vec::new(),
                to_read: Cursor::new(Vec::new()),
                write_err: Some(kind),
            }
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.to_read).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(kind) = self.write_err {
                return Poll::Ready(Err(io::Error::new(kind, "mock write failure")));
            }
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Build a wire-format response frame: 4-byte BE length prefix + LZ4-compressed payload.
    fn build_response(payload: &[u8]) -> Vec<u8> {
        let compressed = compress(payload);
        let len = u32::try_from(compressed.len()).unwrap();
        let mut buf = Vec::with_capacity(4 + compressed.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&compressed);
        buf
    }

    fn make_pending() -> (
        PendingRequest,
        oneshot::Receiver<Result<Vec<u8>, NetworkError>>,
    ) {
        let (tx, rx) = oneshot::channel();
        let req = PendingRequest {
            type_id: "test.req",
            data: vec![1, 2, 3],
            timeout: Duration::from_secs(1),
            resp_tx: tx,
        };
        (req, rx)
    }

    #[tokio::test]
    async fn request_response_round_trips_request_and_response() {
        let response_payload = b"hello response";
        let request_payload = b"request body bytes";
        let request_type_id = "test.req";

        let mut stream = MockStream::new(build_response(response_payload));
        let outcome = do_request_response(&mut stream, request_type_id, request_payload).await;

        match outcome {
            IoOutcome::Ok(bytes) => assert_eq!(bytes, response_payload),
            other => panic!("expected Ok with decoded response, got {other:?}"),
        }

        // The request must have hit the wire as a well-formed typed frame
        // matching what an inbound router would parse.
        let mut written = Cursor::new(stream.written);
        let (parsed_type_id, parsed_payload, _) = read_typed_frame(&mut written, MAX_FRAME_SIZE)
            .await
            .expect("written request must round-trip through read_typed_frame");
        assert_eq!(parsed_type_id, request_type_id);
        assert_eq!(parsed_payload, request_payload);
    }

    #[tokio::test]
    async fn request_response_write_failure_yields_write_failed() {
        let mut stream = MockStream::failing_writes(io::ErrorKind::BrokenPipe);
        let outcome = do_request_response(&mut stream, "test.req", b"body").await;
        assert!(
            matches!(outcome, IoOutcome::WriteFailed(NetworkError::StreamIo(_))),
            "expected WriteFailed(StreamIo), got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn request_response_truncated_length_prefix_yields_response_failed() {
        // Writes succeed but the read side has only 2 bytes — read_frame_len needs 4.
        let mut stream = MockStream::new(vec![0, 0]);
        let outcome = do_request_response(&mut stream, "test.req", b"body").await;
        assert!(
            matches!(
                outcome,
                IoOutcome::ResponseFailed(NetworkError::StreamIo(_))
            ),
            "expected ResponseFailed(StreamIo) for truncated length prefix, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn request_response_truncated_body_yields_response_failed() {
        // Length prefix says 1000 bytes, body has only 10 — read_exact fails.
        let mut response = 1000u32.to_be_bytes().to_vec();
        response.extend_from_slice(&[0u8; 10]);
        let mut stream = MockStream::new(response);
        let outcome = do_request_response(&mut stream, "test.req", b"body").await;
        assert!(
            matches!(
                outcome,
                IoOutcome::ResponseFailed(NetworkError::StreamIo(_))
            ),
            "expected ResponseFailed(StreamIo) for truncated body, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn request_response_invalid_compressed_payload_yields_response_failed() {
        // Valid length prefix, but body bytes don't form a valid LZ4 frame.
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut response = u32::try_from(garbage.len()).unwrap().to_be_bytes().to_vec();
        response.extend_from_slice(&garbage);
        let mut stream = MockStream::new(response);
        let outcome = do_request_response(&mut stream, "test.req", b"body").await;
        match outcome {
            IoOutcome::ResponseFailed(NetworkError::StreamIo(ref msg)) => {
                assert!(
                    msg.contains("decompression"),
                    "expected decompression error message, got {msg}"
                );
            }
            other => panic!("expected ResponseFailed(StreamIo) for invalid payload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_response_oversize_response_yields_response_failed() {
        // Length prefix > MAX_FRAME_SIZE causes read_frame_len to bail before reading body.
        let too_large = u32::try_from(MAX_FRAME_SIZE + 1).unwrap();
        let response = too_large.to_be_bytes().to_vec();
        let mut stream = MockStream::new(response);
        let outcome = do_request_response(&mut stream, "test.req", b"body").await;
        match outcome {
            IoOutcome::ResponseFailed(NetworkError::StreamIo(ref msg)) => {
                assert!(
                    msg.contains("read length failed"),
                    "expected length-validation error, got {msg}"
                );
            }
            other => panic!("expected ResponseFailed for oversize response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn drain_fails_every_pending_request() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut receivers = Vec::new();
        for _ in 0..3 {
            let (req, rcv) = make_pending();
            tx.send(req).await.unwrap();
            receivers.push(rcv);
        }

        drain_with_error(&mut rx, || NetworkError::StreamIo("torn down".into()));

        for rcv in receivers {
            let result = rcv.await.expect("response channel still open");
            assert!(matches!(result, Err(NetworkError::StreamIo(ref s)) if s == "torn down"));
        }
    }

    #[tokio::test]
    async fn drain_on_empty_channel_is_noop() {
        let (_tx, mut rx) = mpsc::channel::<PendingRequest>(8);
        // No panic, no requests touched — try_recv finds nothing and returns.
        drain_with_error(&mut rx, || NetworkError::StreamIo("unused".into()));
    }

    #[tokio::test]
    async fn drain_invokes_err_fn_once_per_request() {
        let (tx, mut rx) = mpsc::channel(4);
        let (req1, rcv1) = make_pending();
        let (req2, rcv2) = make_pending();
        tx.send(req1).await.unwrap();
        tx.send(req2).await.unwrap();

        let count = AtomicUsize::new(0);
        drain_with_error(&mut rx, || {
            count.fetch_add(1, Ordering::Relaxed);
            NetworkError::StreamIo("torn down".into())
        });

        // Both receivers see an error, and the closure ran exactly once per
        // drained request (not once total, not once per receiver poll).
        assert!(matches!(
            rcv1.await.unwrap(),
            Err(NetworkError::StreamIo(_))
        ));
        assert!(matches!(
            rcv2.await.unwrap(),
            Err(NetworkError::StreamIo(_))
        ));
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }
}
