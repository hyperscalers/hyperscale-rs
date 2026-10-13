//! Routes the streams a bound peer opens to per-type handlers.
//!
//! Every bound connection gets two accept loops, one per stream direction.
//! A stream's first byte names what it carries: a unidirectional stream of
//! notifications, read frame by frame until the sender finishes it, or a
//! bidirectional stream holding one request, answered and finished.
//!
//! Requests are admitted against a global concurrency limit and a per-peer
//! one, and a peer whose streams keep failing is cooled down, so no single
//! peer (or flood of peers) can exhaust handler capacity. A request refused
//! for capacity is answered as such rather than left to time out.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::{fmt, io};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use hyperscale_metrics::{record_libp2p_bandwidth, set_inbound_streams_in_use};
use hyperscale_network::HandlerRegistry;
use hyperscale_types::ShardId;
use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::io::AsyncReadExt;
use tokio::spawn;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::spawn_blocking;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::framing::{self, FrameError, MAX_FRAME_SIZE};
use crate::protocol::{
    RESPONSE_BUSY, RESPONSE_OK, RESPONSE_SHARD_UNSUPPORTED, RESPONSE_UNKNOWN_TYPE, SHARD_WIRE_LEN,
    STREAM_NOTIFY, STREAM_REQUEST, class_from_byte, class_priority, decode_shard,
};

/// Timeout for reading a stream's header and its request frame.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for writing a response. A response may be the largest frame the
/// protocol allows, and the requester's own timeout stops the stream sooner
/// when it has given up.
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of inbound requests handled concurrently across all peers.
const MAX_INBOUND_CONCURRENT: usize = 128;

/// Maximum number of inbound requests handled concurrently for one peer.
const MAX_INBOUND_PER_PEER: usize = 32;

/// Number of stream failures within [`FAILURE_WINDOW`] before triggering a
/// cooldown. Each failing stream still costs a task and a read, so a peer
/// failing at a high rate would otherwise saturate the runtime.
const FAILURE_THRESHOLD: u32 = 8;

/// Time window for counting failures. Resets when the window elapses.
const FAILURE_WINDOW: Duration = Duration::from_secs(10);

/// Initial cooldown duration after the failure threshold is exceeded.
const INITIAL_COOLDOWN: Duration = Duration::from_secs(1);

/// Maximum cooldown duration (exponential backoff cap).
const MAX_COOLDOWN: Duration = Duration::from_secs(30);

/// Per-peer failure rate tracking state.
struct PeerRateState {
    /// Failures observed in the current window.
    failures: u32,
    /// When the current failure-counting window started.
    window_start: Instant,
    /// Streams are rejected until this time. `None` if the peer is not in
    /// cooldown.
    cooldown_until: Option<Instant>,
    /// Current backoff duration (doubles after each consecutive cooldown).
    backoff: Duration,
}

impl PeerRateState {
    fn new() -> Self {
        Self {
            failures: 0,
            window_start: Instant::now(),
            cooldown_until: None,
            backoff: INITIAL_COOLDOWN,
        }
    }
}

/// Routes inbound streams to per-type handlers via the handler registry.
pub struct InboundRouter {
    registry: Arc<HandlerRegistry>,
    /// Shards this host serves requests for.
    local_shards: Arc<ArcSwap<HashSet<ShardId>>>,
    /// Global concurrency limiter. Each request in flight holds one permit.
    global_semaphore: Arc<Semaphore>,
    /// Per-peer count of requests in flight.
    per_peer: DashMap<EndpointId, AtomicUsize>,
    /// Per-peer failure rate tracking for cooldown.
    per_peer_failures: DashMap<EndpointId, PeerRateState>,
}

impl InboundRouter {
    pub fn new(
        registry: Arc<HandlerRegistry>,
        local_shards: Arc<ArcSwap<HashSet<ShardId>>>,
    ) -> Self {
        Self {
            registry,
            local_shards,
            global_semaphore: Arc::new(Semaphore::new(MAX_INBOUND_CONCURRENT)),
            per_peer: DashMap::new(),
            per_peer_failures: DashMap::new(),
        }
    }

    /// Serve every stream the peer opens on `connection` until it closes.
    pub fn serve(self: &Arc<Self>, connection: &Connection) {
        let peer = connection.remote_id();

        let router = Arc::clone(self);
        let streams = connection.clone();
        spawn(async move {
            while let Ok(stream) = streams.accept_uni().await {
                let router = Arc::clone(&router);
                spawn(async move {
                    let result = router.handle_uni(peer, stream).await;
                    router.record_outcome(peer, &result);
                });
            }
        });

        let router = Arc::clone(self);
        let streams = connection.clone();
        spawn(async move {
            while let Ok((send, recv)) = streams.accept_bi().await {
                let router = Arc::clone(&router);
                spawn(async move {
                    let result = router.handle_bi(peer, send, recv).await;
                    router.record_outcome(peer, &result);
                });
            }
        });
    }

    fn record_outcome(&self, peer: EndpointId, result: &Result<(), StreamError>) {
        match result {
            Ok(()) => self.record_success(peer),
            Err(error) => {
                if !error.is_peer_abandonment() {
                    self.record_failure(peer);
                }
                debug!(peer = %peer.fmt_short(), %error, "Inbound stream failed");
            }
        }
    }

    /// Whether `peer` is cooling down after a run of failed streams. A
    /// lapsed cooldown is cleared and the failure window reset, so the peer
    /// gets a fresh chance; its backoff is kept, so a re-trigger lasts
    /// longer.
    fn cooling_down(&self, peer: EndpointId) -> bool {
        if let Some(mut state) = self.per_peer_failures.get_mut(&peer)
            && let Some(until) = state.cooldown_until
        {
            if Instant::now() < until {
                return true;
            }
            state.cooldown_until = None;
            state.failures = 0;
            state.window_start = Instant::now();
        }
        false
    }

    /// Try to admit an inbound request, checking per-peer and then global
    /// concurrency. Returns `Some(permit)` if admitted.
    fn try_admit(&self, peer: EndpointId) -> Option<OwnedSemaphorePermit> {
        let counter = self
            .per_peer
            .entry(peer)
            .or_insert_with(|| AtomicUsize::new(0));
        let active = counter.fetch_add(1, Ordering::Relaxed);
        drop(counter);
        if active >= MAX_INBOUND_PER_PEER {
            self.release(peer);
            warn!(
                peer = %peer.fmt_short(),
                active,
                limit = MAX_INBOUND_PER_PEER,
                "Refusing inbound request: per-peer limit exceeded"
            );
            return None;
        }

        let Ok(permit) = Arc::clone(&self.global_semaphore).try_acquire_owned() else {
            self.release(peer);
            warn!(
                peer = %peer.fmt_short(),
                limit = MAX_INBOUND_CONCURRENT,
                "Refusing inbound request: global concurrency limit reached"
            );
            return None;
        };
        self.update_inbound_gauge();
        Some(permit)
    }

    /// Give back the per-peer slot an admitted (or just-refused) request
    /// took.
    fn release(&self, peer: EndpointId) {
        if let Some(counter) = self.per_peer.get(&peer) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
        self.update_inbound_gauge();
    }

    fn update_inbound_gauge(&self) {
        let in_use =
            MAX_INBOUND_CONCURRENT.saturating_sub(self.global_semaphore.available_permits());
        set_inbound_streams_in_use("all", in_use);
    }

    /// Record a stream failure for a peer. Past the threshold within the
    /// window, the peer enters an exponential-backoff cooldown during which
    /// its new streams are dropped unread.
    fn record_failure(&self, peer: EndpointId) {
        let now = Instant::now();
        let triggered = {
            let mut state = self
                .per_peer_failures
                .entry(peer)
                .or_insert_with(PeerRateState::new);
            if now.saturating_duration_since(state.window_start) > FAILURE_WINDOW {
                state.failures = 0;
                state.window_start = now;
            }
            state.failures += 1;

            (state.failures >= FAILURE_THRESHOLD && state.cooldown_until.is_none()).then(|| {
                let cooldown = state.backoff;
                state.cooldown_until = Some(now + cooldown);
                state.backoff = (cooldown * 2).min(MAX_COOLDOWN);
                (state.failures, cooldown)
            })
        };
        if let Some((failures, cooldown)) = triggered {
            warn!(
                peer = %peer.fmt_short(),
                failures,
                cooldown_secs = cooldown.as_secs_f32(),
                "Peer entering failure cooldown; its streams will be dropped"
            );
        }
    }

    /// Record a successful stream for a peer, so a recovered peer regains
    /// trust at once.
    fn record_success(&self, peer: EndpointId) {
        if let Some(mut entry) = self.per_peer_failures.get_mut(&peer) {
            let state = entry.value_mut();
            state.failures = 0;
            state.cooldown_until = None;
            state.backoff = INITIAL_COOLDOWN;
        }
    }

    async fn handle_uni(&self, peer: EndpointId, mut recv: RecvStream) -> Result<(), StreamError> {
        if self.cooling_down(peer) {
            return Ok(());
        }
        let mut kind = [0u8; 1];
        AsyncReadExt::read_exact(&mut recv, &mut kind)
            .await
            .map_err(StreamError::Io)?;
        match kind[0] {
            STREAM_NOTIFY => self.read_notifications(peer, recv).await,
            _ => Err(StreamError::UnknownStreamKind),
        }
    }

    /// Dispatch every notification the peer writes to this stream, until it
    /// finishes the stream or the connection closes.
    async fn read_notifications(
        &self,
        peer: EndpointId,
        mut recv: RecvStream,
    ) -> Result<(), StreamError> {
        loop {
            let (type_id, payload, wire_bytes) =
                match framing::read_typed_frame(&mut recv, MAX_FRAME_SIZE).await {
                    Ok(frame) => frame,
                    Err(FrameError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        return Ok(());
                    }
                    Err(e) => return Err(StreamError::Frame(e)),
                };
            record_libp2p_bandwidth(wire_bytes as u64, 0);

            if let Some(handler) = self.registry.get_notification(&type_id) {
                spawn(async move { handler(payload) });
            } else {
                // The sender may follow with types this host does know.
                warn!(
                    peer = %peer.fmt_short(),
                    type_id = %type_id,
                    "Unknown notification type"
                );
            }
        }
    }

    async fn handle_bi(
        &self,
        peer: EndpointId,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<(), StreamError> {
        if self.cooling_down(peer) {
            return Ok(());
        }
        let mut kind = [0u8; 1];
        timeout(
            REQUEST_READ_TIMEOUT,
            AsyncReadExt::read_exact(&mut recv, &mut kind),
        )
        .await
        .map_err(|_| StreamError::Timeout)?
        .map_err(StreamError::Io)?;
        if kind[0] != STREAM_REQUEST {
            return Err(StreamError::UnknownStreamKind);
        }

        let Some(permit) = self.try_admit(peer) else {
            return respond_status(&mut send, RESPONSE_BUSY).await;
        };
        let result = self.serve_request(send, recv).await;
        drop(permit);
        self.release(peer);
        result
    }

    /// Read one request, run its handler, and write the response.
    async fn serve_request(
        &self,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<(), StreamError> {
        let (class, shard, type_id, payload) = timeout(REQUEST_READ_TIMEOUT, async {
            let mut header = [0u8; 1 + SHARD_WIRE_LEN];
            AsyncReadExt::read_exact(&mut recv, &mut header)
                .await
                .map_err(StreamError::Io)?;
            let class = class_from_byte(header[0]).ok_or(StreamError::MalformedHeader)?;
            let mut shard_bytes = [0u8; SHARD_WIRE_LEN];
            shard_bytes.copy_from_slice(&header[1..]);
            let shard = decode_shard(shard_bytes).ok_or(StreamError::MalformedHeader)?;
            let (type_id, payload, wire_bytes) =
                framing::read_typed_frame(&mut recv, MAX_FRAME_SIZE)
                    .await
                    .map_err(StreamError::Frame)?;
            record_libp2p_bandwidth((header.len() + wire_bytes) as u64, 0);
            Ok::<_, StreamError>((class, shard, type_id, payload))
        })
        .await
        .map_err(|_| StreamError::Timeout)??;

        // The response competes for the connection at its request's class.
        // The stream is ours alone and open, so this cannot fail.
        let _ = send.set_priority(class_priority(class));

        if !self.local_shards.load().contains(&shard) {
            return respond_status(&mut send, RESPONSE_SHARD_UNSUPPORTED).await;
        }
        let Some(handler) = self.registry.get_request(&type_id, shard) else {
            respond_status(&mut send, RESPONSE_UNKNOWN_TYPE).await?;
            return Err(StreamError::UnknownMessageType);
        };

        // Handlers do heavy work (merkle proof generation) that would starve
        // the async runtime on a worker thread.
        let response = spawn_blocking(move || handler(&payload))
            .await
            .expect("request handler task panicked");

        let wire_bytes = timeout(RESPONSE_WRITE_TIMEOUT, async {
            send.write_all(&[RESPONSE_OK])
                .await
                .map_err(StreamError::io)?;
            let wire_bytes = framing::write_frame(&mut send, &response)
                .await
                .map_err(StreamError::Io)?;
            send.finish().map_err(StreamError::io)?;
            // Hold the stream until the requester has the response or has
            // stopped reading; dropping it sooner would reset unsent data.
            let _ = send.stopped().await;
            Ok::<_, StreamError>(wire_bytes)
        })
        .await
        .map_err(|_| StreamError::Timeout)??;
        record_libp2p_bandwidth(0, 1 + wire_bytes as u64);
        Ok(())
    }
}

/// Answer a request with a bare status and finish the stream.
async fn respond_status(send: &mut SendStream, status: u8) -> Result<(), StreamError> {
    send.write_all(&[status]).await.map_err(StreamError::io)?;
    send.finish().map_err(StreamError::io)?;
    let _ = timeout(REQUEST_READ_TIMEOUT, send.stopped()).await;
    Ok(())
}

/// Errors that can occur during stream handling.
#[derive(Debug)]
enum StreamError {
    Timeout,
    Io(io::Error),
    Frame(FrameError),
    UnknownStreamKind,
    MalformedHeader,
    UnknownMessageType,
}

impl StreamError {
    fn io(error: impl Into<io::Error>) -> Self {
        Self::Io(error.into())
    }

    /// Whether the error was caused by the peer closing or resetting the
    /// stream rather than a protocol violation or a local fault. Requesters
    /// abandon streams as a normal part of their retry strategy, so these
    /// must not count toward the per-peer failure threshold.
    fn is_peer_abandonment(&self) -> bool {
        let io_kind = match self {
            Self::Io(e) | Self::Frame(FrameError::Io(e)) => Some(e.kind()),
            _ => None,
        };
        matches!(
            io_kind,
            Some(
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected
            )
        )
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "stream timeout"),
            Self::Io(e) => write!(f, "stream I/O error: {e}"),
            Self::Frame(e) => write!(f, "stream frame error: {e}"),
            Self::UnknownStreamKind => write!(f, "unknown stream kind"),
            Self::MalformedHeader => write!(f, "malformed stream header"),
            Self::UnknownMessageType => write!(f, "unknown message type"),
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    fn random_peer() -> EndpointId {
        SecretKey::generate().public()
    }

    fn make_router(global_cap: usize) -> InboundRouter {
        InboundRouter {
            global_semaphore: Arc::new(Semaphore::new(global_cap)),
            ..InboundRouter::new(
                Arc::new(HandlerRegistry::default()),
                Arc::new(ArcSwap::from_pointee(HashSet::new())),
            )
        }
    }

    fn peer_count(router: &InboundRouter, peer: EndpointId) -> usize {
        router
            .per_peer
            .get(&peer)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// Snapshot the failure-tracking state for `peer`.
    fn failure_state(
        router: &InboundRouter,
        peer: EndpointId,
    ) -> Option<(u32, Option<Instant>, Duration)> {
        let entry = router.per_peer_failures.get(&peer)?;
        Some((entry.failures, entry.cooldown_until, entry.backoff))
    }

    #[tokio::test]
    async fn the_per_peer_cap_refuses_without_leaking_its_slot() {
        let router = make_router(MAX_INBOUND_PER_PEER * 2);
        let peer = random_peer();

        // Dropping a permit frees the global slot only, so the per-peer
        // count climbs as it would with every request still in flight.
        for _ in 0..MAX_INBOUND_PER_PEER {
            assert!(router.try_admit(peer).is_some(), "under cap");
        }
        assert!(router.try_admit(peer).is_none(), "at cap");
        assert_eq!(
            peer_count(&router, peer),
            MAX_INBOUND_PER_PEER,
            "a refusal rolls back its speculative increment"
        );

        router.release(peer);
        assert!(
            router.try_admit(peer).is_some(),
            "a finished request frees its slot"
        );
    }

    #[tokio::test]
    async fn one_saturated_peer_leaves_another_admittable() {
        let router = make_router(MAX_INBOUND_PER_PEER * 4);
        let a = random_peer();
        let b = random_peer();
        for _ in 0..MAX_INBOUND_PER_PEER {
            assert!(router.try_admit(a).is_some());
        }
        assert!(router.try_admit(a).is_none());
        assert!(router.try_admit(b).is_some());
    }

    #[tokio::test]
    async fn the_global_cap_refuses_without_charging_the_peer() {
        let router = make_router(2);
        let a = random_peer();
        let b = random_peer();
        let _p1 = router.try_admit(a).expect("first slot");
        let _p2 = router.try_admit(a).expect("second slot");

        assert!(router.try_admit(b).is_none(), "global cap refuses");
        assert_eq!(peer_count(&router, b), 0);
    }

    #[tokio::test]
    async fn failures_past_the_threshold_cool_the_peer_down() {
        let router = make_router(8);
        let peer = random_peer();

        for _ in 0..FAILURE_THRESHOLD - 1 {
            router.record_failure(peer);
        }
        assert!(!router.cooling_down(peer), "below the threshold");

        router.record_failure(peer);
        assert!(router.cooling_down(peer), "at the threshold");
        let (_, _, backoff) = failure_state(&router, peer).expect("entry exists");
        assert_eq!(
            backoff,
            INITIAL_COOLDOWN * 2,
            "the next cooldown is doubled"
        );
    }

    #[tokio::test]
    async fn a_lapsed_cooldown_admits_again_and_keeps_its_backoff() {
        let router = make_router(8);
        let peer = random_peer();
        router.per_peer_failures.insert(
            peer,
            PeerRateState {
                failures: FAILURE_THRESHOLD,
                window_start: Instant::now(),
                cooldown_until: Instant::now().checked_sub(Duration::from_millis(1)),
                backoff: INITIAL_COOLDOWN * 2,
            },
        );

        assert!(!router.cooling_down(peer));
        let (failures, cooldown_until, backoff) =
            failure_state(&router, peer).expect("entry exists");
        assert_eq!(failures, 0);
        assert!(cooldown_until.is_none());
        assert_eq!(backoff, INITIAL_COOLDOWN * 2);
    }

    #[tokio::test]
    async fn a_success_restores_a_peer_at_once() {
        let router = make_router(8);
        let peer = random_peer();
        for _ in 0..FAILURE_THRESHOLD {
            router.record_failure(peer);
        }
        router.record_success(peer);

        assert!(!router.cooling_down(peer));
        let (failures, _, backoff) = failure_state(&router, peer).expect("entry exists");
        assert_eq!(failures, 0);
        assert_eq!(backoff, INITIAL_COOLDOWN);
    }

    #[test]
    fn a_stream_the_peer_abandoned_is_not_a_failure() {
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::NotConnected,
        ] {
            assert!(StreamError::Io(io::Error::new(kind, "test")).is_peer_abandonment());
            assert!(
                StreamError::Frame(FrameError::Io(io::Error::new(kind, "test")))
                    .is_peer_abandonment()
            );
        }
        for error in [
            StreamError::Timeout,
            StreamError::UnknownStreamKind,
            StreamError::MalformedHeader,
            StreamError::UnknownMessageType,
            StreamError::Io(io::Error::new(io::ErrorKind::InvalidData, "test")),
            StreamError::Frame(FrameError::TooLarge(1_000_000)),
        ] {
            assert!(!error.is_peer_abandonment(), "{error:?} is a real failure");
        }
    }
}
