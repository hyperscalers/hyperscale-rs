//! Request/response over one stream per request.
//!
//! Each request opens its own bidirectional stream on the connection to its
//! peer, writes a header and one typed frame, finishes its side, and reads a
//! status byte and one response frame. Streams are cheap and independent, so
//! a large or slow exchange never holds another request to the same peer
//! behind it, and the stream's priority follows the request's class.
//!
//! ```text
//! Requester                                                   Responder
//!     ── [kind][class][shard][typed request frame], finish ────────▶
//!     ◀── [status][response frame], finish
//! ```
//!
//! A peer is sent at most [`SHEDDABLE_PER_PEER`] `Recovery` and `Bulk`
//! requests at a time; the rest wait their turn inside their own timeout.
//! A sheddable request its caller stops waiting for keeps its turn until
//! the responder has answered or given up, because the responder is still
//! working on it.
//!
//! A peer that cannot be reached, or that answers that it does not serve the
//! shard, is backed off per `(peer, shard)` so peer selection skips it
//! instead of failing against it again at once. A peer on a relayed path is
//! held back the same way for the classes that path does not carry, so such
//! a request goes to a member on a direct path instead.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use hyperscale_metrics::record_libp2p_bandwidth;
use hyperscale_network::compression::compress;
use hyperscale_network::fault::Tier;
use hyperscale_network::retry::uses_relaxed_retry;
use hyperscale_network::stream_backoff::StreamFailure;
use hyperscale_types::{MessageClass, ShardId};
use iroh::EndpointId;
use tokio::io::AsyncReadExt;
use tokio::spawn;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, sleep, timeout as tokio_timeout};
use tracing::debug;

use crate::endpoint::IrohAdapter;
use crate::error::NetworkError;
use crate::framing::{self, MAX_FRAME_SIZE};
use crate::peer_backoff::{self, BackoffState};
use crate::protocol::{
    RESPONSE_BUSY, RESPONSE_OK, RESPONSE_RELAYED, RESPONSE_SHARD_UNSUPPORTED,
    RESPONSE_UNKNOWN_TYPE, STREAM_REQUEST, class_priority, encode_shard,
};

/// Abstraction over sending one request attempt to one peer.
///
/// Lets [`RequestManager`] swap in a deterministic mock for retry-loop tests
/// without standing up a real transport. The trait is object-safe, so the
/// manager holds it as a trait object.
///
/// [`RequestManager`]: crate::RequestManager
pub trait RequestPool: Send + Sync + 'static {
    /// Send a request for `shard` to `peer` and await the response.
    ///
    /// `timeout` bounds the I/O for this attempt. The future is boxed
    /// because the trait is object-safe; the `'a` lifetime lets
    /// implementations borrow from `&self`.
    fn send<'a>(
        &'a self,
        peer: EndpointId,
        shard: ShardId,
        type_id: &'static str,
        data: Vec<u8>,
        class: MessageClass,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, NetworkError>> + Send + 'a>>;

    /// How much longer a request of `class` for `shard` should stay away
    /// from `peer`, or `None` when it is usable. The request manager
    /// consults this so peer selection skips a peer that would only
    /// instant-fail, and surfaces the soonest reopening when every
    /// candidate is held rather than spinning. Defaults to `None` for pools
    /// with no backoff layer.
    fn backed_off_for(
        &self,
        _peer: EndpointId,
        _shard: ShardId,
        _class: MessageClass,
    ) -> Option<Duration> {
        None
    }
}

/// How long a request stays away from a peer whose relayed path does not
/// carry its class before the path is looked at again.
const RELAYED_RETRY: Duration = Duration::from_secs(5);

/// Requests of the sheddable classes (`Recovery`, `Bulk`) in flight to one
/// peer at a time. Every request opens a stream of its own, so nothing else
/// holds a sync's parallel fetches below the responder's per-peer cap; past
/// it the responder refuses, the requester retries, and the responder's
/// slots stay full of work whose requester has already given up.
const SHEDDABLE_PER_PEER: usize = 4;

/// Longest an abandoned sheddable exchange keeps its turn: the responder's
/// own bound on writing a response.
const ABANDONED_EXCHANGE_LIMIT: Duration = Duration::from_secs(30);

/// Sends each request on a stream of its own.
pub struct RequestStreams {
    adapter: Arc<IrohAdapter>,
    backoff: DashMap<(EndpointId, ShardId), BackoffState>,
    /// Turns for sheddable requests to each peer.
    sheddable: DashMap<EndpointId, Arc<Semaphore>>,
    /// Per-request outbound delay (`Duration::ZERO` in production).
    latency: Duration,
}

impl RequestStreams {
    /// Build request streams over `adapter`'s connections.
    #[must_use]
    pub fn new(adapter: Arc<IrohAdapter>, latency: Duration) -> Self {
        Self {
            adapter,
            backoff: DashMap::new(),
            sheddable: DashMap::new(),
            latency,
        }
    }

    /// The turns a request of `class` to `peer` waits on, if its class has
    /// any.
    fn turns(&self, peer: EndpointId, class: MessageClass) -> Option<Arc<Semaphore>> {
        uses_relaxed_retry(class).then(|| {
            Arc::clone(
                &self
                    .sheddable
                    .entry(peer)
                    .or_insert_with(|| Arc::new(Semaphore::new(SHEDDABLE_PER_PEER))),
            )
        })
    }

    async fn send_request(
        &self,
        peer: EndpointId,
        shard: ShardId,
        type_id: &'static str,
        data: Vec<u8>,
        class: MessageClass,
        timeout: Duration,
    ) -> Result<Vec<u8>, NetworkError> {
        // Fault gate: drop this request leg per attempt. A dropped leg never
        // reaches the peer, so it surfaces as a timeout: what the retry loop
        // sees on real packet loss, re-rolled on the next attempt.
        if self
            .adapter
            .fault_gate()
            .drop_outbound(peer, type_id, Tier::Request)
        {
            return Err(NetworkError::Timeout);
        }

        // Hold the request for the simulated one-way delay before it hits
        // the wire, outside the I/O timeout so it does not eat that budget.
        if !self.latency.is_zero() {
            sleep(self.latency).await;
        }

        let key = (peer, shard);
        let deadline = Instant::now() + timeout;
        let adapter = Arc::clone(&self.adapter);
        let outcome = match self.turns(peer, class) {
            None => tokio_timeout(
                timeout,
                exchange(adapter, peer, shard, type_id, data, class),
            )
            .await
            .unwrap_or(Err(NetworkError::Timeout)),
            Some(turns) => match tokio_timeout(timeout, turns.acquire_owned()).await {
                Ok(Ok(turn)) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let held = spawn(exchange_holding(
                        turn, adapter, peer, shard, type_id, data, class,
                    ));
                    match tokio_timeout(remaining, held).await {
                        Ok(Ok(outcome)) => outcome,
                        Ok(Err(_)) => Err(NetworkError::StreamIo("request task ended".into())),
                        Err(_) => Err(NetworkError::Timeout),
                    }
                }
                // The semaphore is never closed; only the wait can run out.
                Ok(Err(_)) | Err(_) => Err(NetworkError::Timeout),
            },
        };
        match &outcome {
            Ok(_) => {
                self.backoff.remove(&key);
            }
            Err(NetworkError::ShardUnsupported(_)) => {
                peer_backoff::apply_backoff(&self.backoff, &key, StreamFailure::Unsupported);
            }
            // A relayed path holds the peer back by its own state until it
            // changes. A timeout means the peer is slow or the frame was
            // lost; its stream died with this request and the next opens
            // afresh.
            Err(NetworkError::RelayedPath | NetworkError::Timeout) => {}
            Err(error) => {
                debug!(peer = %peer.fmt_short(), shard = shard.inner(), %error, "Request stream failed");
                peer_backoff::apply_backoff(&self.backoff, &key, StreamFailure::Transient);
            }
        }
        outcome
    }
}

/// A sheddable exchange that keeps `turn` until it ends, whether or not its
/// caller is still waiting, for at most [`ABANDONED_EXCHANGE_LIMIT`].
async fn exchange_holding(
    turn: OwnedSemaphorePermit,
    adapter: Arc<IrohAdapter>,
    peer: EndpointId,
    shard: ShardId,
    type_id: &'static str,
    data: Vec<u8>,
    class: MessageClass,
) -> Result<Vec<u8>, NetworkError> {
    let outcome = tokio_timeout(
        ABANDONED_EXCHANGE_LIMIT,
        exchange(adapter, peer, shard, type_id, data, class),
    )
    .await
    .unwrap_or(Err(NetworkError::Timeout));
    drop(turn);
    outcome
}

/// One request and its response on a fresh stream.
async fn exchange(
    adapter: Arc<IrohAdapter>,
    peer: EndpointId,
    shard: ShardId,
    type_id: &'static str,
    data: Vec<u8>,
    class: MessageClass,
) -> Result<Vec<u8>, NetworkError> {
    let compressed = compress(&data);
    if !adapter.paths().admit(peer, class, compressed.len()) {
        return Err(NetworkError::RelayedPath);
    }
    let (mut send, mut recv) = adapter.open_bi(peer).await?;
    // The stream is ours alone and open, so setting its priority cannot
    // fail.
    let _ = send.set_priority(class_priority(class));

    let mut header = Vec::with_capacity(2 + encode_shard(shard).len());
    header.push(STREAM_REQUEST);
    header.push(class as u8);
    header.extend_from_slice(&encode_shard(shard));
    send.write_all(&header).await.map_err(stream_io)?;
    let wire_bytes = framing::write_precompressed_typed_frame(&mut send, type_id, &compressed)
        .await
        .map_err(stream_io)?;
    send.finish().map_err(stream_io)?;
    record_libp2p_bandwidth(0, (header.len() + wire_bytes) as u64);

    let mut status = [0u8; 1];
    AsyncReadExt::read_exact(&mut recv, &mut status)
        .await
        .map_err(stream_io)?;
    match status[0] {
        RESPONSE_OK => {}
        RESPONSE_SHARD_UNSUPPORTED => {
            return Err(NetworkError::ShardUnsupported(format!(
                "shard {}",
                shard.inner()
            )));
        }
        RESPONSE_UNKNOWN_TYPE => {
            return Err(NetworkError::StreamIo(format!(
                "peer has no handler for {type_id}"
            )));
        }
        RESPONSE_BUSY => return Err(NetworkError::StreamIo("peer is busy".into())),
        RESPONSE_RELAYED => return Err(NetworkError::RelayedPath),
        other => {
            return Err(NetworkError::StreamIo(format!(
                "unknown response status {other}"
            )));
        }
    }
    let response = framing::read_frame(&mut recv, MAX_FRAME_SIZE)
        .await
        .map_err(|e| NetworkError::StreamIo(e.to_string()))?;
    record_libp2p_bandwidth(response.len() as u64, 0);
    Ok(response)
}

fn stream_io(error: impl Into<io::Error>) -> NetworkError {
    NetworkError::StreamIo(error.into().to_string())
}

impl RequestPool for RequestStreams {
    fn send<'a>(
        &'a self,
        peer: EndpointId,
        shard: ShardId,
        type_id: &'static str,
        data: Vec<u8>,
        class: MessageClass,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, NetworkError>> + Send + 'a>> {
        Box::pin(self.send_request(peer, shard, type_id, data, class, timeout))
    }

    fn backed_off_for(
        &self,
        peer: EndpointId,
        shard: ShardId,
        class: MessageClass,
    ) -> Option<Duration> {
        if !self.adapter.paths().carries(peer, class) {
            return Some(RELAYED_RETRY);
        }
        peer_backoff::backed_off_for(&self.backoff, &(peer, shard))
    }
}
