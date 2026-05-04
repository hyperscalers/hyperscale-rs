//! Routes inbound network requests to per-type handlers.
//!
//! This component accepts incoming streams from peers and dispatches them to
//! the appropriate handler based on the request `type_id` in the frame header.
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
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

/// Timeout for reading requests and writing responses on streams.
const STREAM_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Idle timeout for persistent notification streams.
///
/// If no frame is received within this period, the stream is closed.
/// The sender will detect the write error and reconnect when it has
/// more frames to send. Longer than QUIC idle timeout (30s) so QUIC
/// keep-alive handles liveness detection; this just prevents resource
/// leaks if a sender silently disappears.
const PERSISTENT_STREAM_IDLE_TIMEOUT: Duration = Duration::from_mins(1);

/// Maximum number of inbound streams handled concurrently across all peers.
const MAX_INBOUND_CONCURRENT: usize = 128;

/// Maximum number of concurrent inbound streams from a single peer.
const MAX_INBOUND_PER_PEER: usize = 16;

/// Number of stream failures within [`FAILURE_WINDOW`] before triggering a cooldown.
///
/// When a peer's streams fail at high rate (e.g. the peer is crash-looping or its
/// transport is broken), each failure still spawns a tokio task, reads from the
/// QUIC stream, and logs a warning. At 18+ failures/sec this saturates the runtime.
const FAILURE_THRESHOLD: u32 = 8;

/// Time window for counting failures. Resets when the window elapses.
const FAILURE_WINDOW: Duration = Duration::from_secs(10);

/// Initial cooldown duration after the failure threshold is exceeded.
const INITIAL_COOLDOWN: Duration = Duration::from_secs(1);

/// Maximum cooldown duration (exponential backoff cap).
const MAX_COOLDOWN: Duration = Duration::from_secs(30);

/// Per-peer failure rate tracking state.
///
/// Lives inside the `per_peer_failures` `DashMap` and is accessed from both the
/// accept loop (to check cooldown) and stream handler tasks (to record outcomes).
struct PeerRateState {
    /// Failures observed in the current window.
    failures: u32,
    /// When the current failure-counting window started.
    window_start: Instant,
    /// Streams are rejected until this time. `None` if the peer is not in cooldown.
    cooldown_until: Option<Instant>,
    /// Current backoff duration (doubles after each consecutive cooldown trigger).
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

/// Handle for the inbound router tasks.
///
/// Kept alive inside `Libp2pNetwork` to prevent the tokio tasks from being
/// aborted when the `JoinHandle`s are dropped.
pub struct InboundRouterHandle {
    #[allow(dead_code)]
    request_handle: tokio::task::JoinHandle<()>,
    #[allow(dead_code)]
    notify_handle: tokio::task::JoinHandle<()>,
}

/// Routes inbound requests to per-type handlers via the handler registry.
///
/// The router accepts incoming streams and for each:
/// 1. Checks per-peer and global concurrency limits
/// 2. Reads the typed frame header (`type_id`) + compressed SBOR payload
/// 3. Looks up the handler in the registry and calls it with the SBOR payload
/// 4. Compresses and writes the length-prefixed response
/// 5. Closes the stream
struct InboundRouter {
    registry: Arc<HandlerRegistry>,
    /// Global concurrency limiter. Each active stream holds one permit.
    global_semaphore: Arc<Semaphore>,
    /// Per-peer active stream count.
    per_peer: Arc<DashMap<PeerId, AtomicUsize>>,
    /// Per-peer failure rate tracking for cooldown.
    per_peer_failures: Arc<DashMap<PeerId, PeerRateState>>,
}

impl InboundRouter {
    /// Spawn the inbound router as two background tasks (request + notification).
    ///
    /// The router will accept incoming streams until the stream control is dropped.
    fn spawn(adapter: &Arc<Libp2pAdapter>, registry: Arc<HandlerRegistry>) -> InboundRouterHandle {
        let router = Arc::new(Self {
            registry,
            global_semaphore: Arc::new(Semaphore::new(MAX_INBOUND_CONCURRENT)),
            per_peer: Arc::new(DashMap::new()),
            per_peer_failures: Arc::new(DashMap::new()),
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
                            match result {
                                Ok(()) => router_clone.record_success(&peer_id),
                                Err(ref e) => {
                                    if !e.is_client_abandonment() {
                                        router_clone.record_failure(&peer_id);
                                    }
                                    debug!(peer = %peer_id, error = ?e, "Request stream handling failed");
                                }
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
            let router = router;
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
                            match result {
                                Ok(()) => router_clone.record_success(&peer_id),
                                Err(ref e) => {
                                    if !e.is_client_abandonment() {
                                        router_clone.record_failure(&peer_id);
                                    }
                                    debug!(peer = %peer_id, error = ?e, "Notification stream handling failed");
                                }
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

    /// Try to admit an inbound stream, checking failure-rate cooldown,
    /// per-peer concurrency, and global concurrency limits (in that order).
    ///
    /// Returns `Some(permit)` if admitted, `None` if rejected.
    fn try_admit(self: &Arc<Self>, peer_id: &PeerId) -> Option<tokio::sync::OwnedSemaphorePermit> {
        // ── Failure-rate cooldown check ──
        if let Some(mut state) = self.per_peer_failures.get_mut(peer_id)
            && let Some(until) = state.cooldown_until
        {
            if Instant::now() < until {
                // Peer is in cooldown — silently drop without logging each
                // stream (the cooldown-start log is sufficient).
                return None;
            }
            // Cooldown expired — clear it and reset the failure window so
            // the peer gets a fresh chance. Backoff is preserved so the
            // next cooldown (if it re-triggers) uses a longer duration.
            state.cooldown_until = None;
            state.failures = 0;
            state.window_start = Instant::now();
        }

        // ── Per-peer concurrency check ──
        let peer_counter = self
            .per_peer
            .entry(*peer_id)
            .or_insert_with(|| AtomicUsize::new(0));
        let prev = peer_counter.fetch_add(1, Ordering::Relaxed);
        drop(peer_counter);
        if prev >= MAX_INBOUND_PER_PEER {
            self.decrement_peer_count(peer_id);
            warn!(
                peer = %peer_id,
                active = prev,
                limit = MAX_INBOUND_PER_PEER,
                "Dropping inbound stream: per-peer limit exceeded"
            );
            return None;
        }

        // ── Global concurrency check ──
        let Ok(permit) = self.global_semaphore.clone().try_acquire_owned() else {
            self.decrement_peer_count(peer_id);
            warn!(
                peer = %peer_id,
                limit = MAX_INBOUND_CONCURRENT,
                "Dropping inbound stream: global concurrency limit reached"
            );
            return None;
        };
        self.update_inbound_gauge();
        Some(permit)
    }

    /// Decrement the per-peer active stream counter.
    fn decrement_peer_count(&self, peer_id: &PeerId) {
        if let Some(counter) = self.per_peer.get(peer_id) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
        self.update_inbound_gauge();
    }

    /// Update the global inbound-streams-in-use gauge from the semaphore.
    /// Cheap (atomic read) and the only place we centrally know the
    /// occupancy without threading a counter through every spawn site.
    fn update_inbound_gauge(&self) {
        let in_use =
            MAX_INBOUND_CONCURRENT.saturating_sub(self.global_semaphore.available_permits());
        metrics::set_inbound_streams_in_use("all", in_use);
    }

    /// Record a stream failure for a peer. If failures exceed the threshold
    /// within the time window, the peer enters an exponential-backoff cooldown
    /// during which all new streams are silently dropped.
    #[allow(clippy::significant_drop_tightening)] // entry lock needed for full update
    fn record_failure(&self, peer_id: &PeerId) {
        let now = Instant::now();
        let mut entry = self
            .per_peer_failures
            .entry(*peer_id)
            .or_insert_with(PeerRateState::new);
        let state = entry.value_mut();

        // Reset window if expired.
        if now.duration_since(state.window_start) > FAILURE_WINDOW {
            state.failures = 0;
            state.window_start = now;
        }

        state.failures += 1;

        if state.failures >= FAILURE_THRESHOLD && state.cooldown_until.is_none() {
            let cooldown = state.backoff;
            state.cooldown_until = Some(now + cooldown);
            // Double backoff for next trigger, capped.
            state.backoff = (cooldown * 2).min(MAX_COOLDOWN);
            warn!(
                peer = %peer_id,
                failures = state.failures,
                cooldown_secs = cooldown.as_secs_f32(),
                "Peer entering failure cooldown — streams will be dropped"
            );
        }
    }

    /// Record a successful stream for a peer. Resets failure tracking so
    /// recovered peers regain trust immediately.
    fn record_success(&self, peer_id: &PeerId) {
        if let Some(mut entry) = self.per_peer_failures.get_mut(peer_id) {
            let state = entry.value_mut();
            state.failures = 0;
            state.cooldown_until = None;
            state.backoff = INITIAL_COOLDOWN;
        }
    }

    /// Handle a persistent inbound request stream.
    ///
    /// Loops reading typed request frames and writing response frames until
    /// the client closes the stream or the idle timeout elapses. Matches the
    /// notification-stream pattern — one stream per peer, many request/response
    /// pairs.
    async fn handle_request_stream(
        &self,
        peer: PeerId,
        mut stream: Stream,
    ) -> Result<(), StreamError> {
        loop {
            // Read the next request frame (idle timeout between requests).
            let read_result = tokio::time::timeout(
                PERSISTENT_STREAM_IDLE_TIMEOUT,
                stream_framing::read_typed_frame(&mut stream, MAX_FRAME_SIZE),
            )
            .await;

            let (type_id, sbor_payload, req_wire_bytes) = match read_result {
                Ok(Ok(frame)) => frame,
                Ok(Err(FrameError::Io(ref e))) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Client closed the stream cleanly between requests.
                    debug!(%peer, "Request stream closed by sender");
                    return Ok(());
                }
                Ok(Err(e)) => return Err(StreamError::Frame(e)),
                Err(_) => {
                    // Idle timeout — close our side. Client will reconnect
                    // on next request.
                    debug!(%peer, "Request stream idle timeout, closing");
                    return Ok(());
                }
            };

            metrics::record_libp2p_bandwidth(req_wire_bytes as u64, 0);

            // Look up the per-type request handler.
            let handler = self
                .registry
                .get_request(&type_id)
                .ok_or(StreamError::UnknownMessageType)?;

            // Delegate to the handler on the blocking thread pool.
            // Handlers like provision.request do heavy work (merkle proof
            // generation) that would starve the async runtime if run on a
            // worker thread.
            let response_sbor = tokio::task::spawn_blocking(move || handler(&sbor_payload))
                .await
                .expect("request handler task panicked");

            // Write length-prefixed compressed response with timeout.
            let resp_wire_bytes = tokio::time::timeout(
                STREAM_IO_TIMEOUT,
                stream_framing::write_frame(&mut stream, &response_sbor),
            )
            .await
            .map_err(|_| StreamError::Timeout)?
            .map_err(StreamError::Io)?;

            metrics::record_libp2p_bandwidth(0, resp_wire_bytes as u64);
        }
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
                warn!(
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
pub fn spawn_inbound_router(
    adapter: &Arc<Libp2pAdapter>,
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

impl StreamError {
    /// Whether the error was caused by the peer closing/resetting the stream
    /// rather than a protocol violation or a local fault. Speculative-retry
    /// clients abandon streams as a normal part of their retry strategy, so
    /// these must not count toward the per-peer failure threshold.
    fn is_client_abandonment(&self) -> bool {
        let io_kind = match self {
            Self::Io(e) | Self::Frame(FrameError::Io(e)) => Some(e.kind()),
            _ => None,
        };
        matches!(
            io_kind,
            Some(
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            )
        )
    }
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "stream timeout"),
            Self::Io(e) => write!(f, "stream I/O error: {e}"),
            Self::Frame(e) => write!(f, "stream frame error: {e}"),
            Self::UnknownMessageType => write!(f, "unknown message type"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_router(global_cap: usize) -> Arc<InboundRouter> {
        Arc::new(InboundRouter {
            registry: Arc::new(HandlerRegistry::new()),
            global_semaphore: Arc::new(Semaphore::new(global_cap)),
            per_peer: Arc::new(DashMap::new()),
            per_peer_failures: Arc::new(DashMap::new()),
        })
    }

    fn peer_count(router: &InboundRouter, peer: &PeerId) -> usize {
        router
            .per_peer
            .get(peer)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// Snapshot the failure-tracking state for `peer`, dropping the
    /// `DashMap` borrow before returning so callers can assert without
    /// holding a lock across the assertion.
    fn failure_state(
        router: &InboundRouter,
        peer: &PeerId,
    ) -> Option<(u32, Option<Instant>, Duration)> {
        let entry = router.per_peer_failures.get(peer)?;
        Some((entry.failures, entry.cooldown_until, entry.backoff))
    }

    #[tokio::test]
    async fn per_peer_cap_rejects_without_leaking_counter() {
        // Global cap large enough that the per-peer cap is the actual gate.
        // We don't need to hold the returned permits — dropping a permit
        // releases the global semaphore slot only, leaving the per-peer
        // counter bumped (which is the state we want to reach).
        let router = make_router(MAX_INBOUND_PER_PEER * 2);
        let peer = PeerId::random();

        for _ in 0..MAX_INBOUND_PER_PEER {
            assert!(router.try_admit(&peer).is_some(), "under cap");
        }
        assert_eq!(peer_count(&router, &peer), MAX_INBOUND_PER_PEER);

        // Over-cap attempt: rejected. The counter must not stay bumped —
        // otherwise a single burst would permanently lock the peer out.
        assert!(
            router.try_admit(&peer).is_none(),
            "per-peer cap should reject"
        );
        assert_eq!(
            peer_count(&router, &peer),
            MAX_INBOUND_PER_PEER,
            "rejection must roll back the speculative increment"
        );
    }

    #[tokio::test]
    async fn per_peer_cap_recovers_after_release() {
        let router = make_router(MAX_INBOUND_PER_PEER * 2);
        let peer = PeerId::random();

        for _ in 0..MAX_INBOUND_PER_PEER {
            assert!(router.try_admit(&peer).is_some(), "under cap");
        }
        assert!(router.try_admit(&peer).is_none(), "at cap");

        // Simulate one stream completing — the accept-loop closure invokes
        // decrement_peer_count once the handler returns.
        router.decrement_peer_count(&peer);

        assert!(
            router.try_admit(&peer).is_some(),
            "released slot should allow re-admission"
        );
    }

    #[tokio::test]
    async fn per_peer_caps_are_isolated() {
        let router = make_router(MAX_INBOUND_PER_PEER * 4);
        let a = PeerId::random();
        let b = PeerId::random();

        for _ in 0..MAX_INBOUND_PER_PEER {
            assert!(router.try_admit(&a).is_some(), "a under cap");
        }
        assert!(router.try_admit(&a).is_none(), "a saturated");

        // Saturating one peer must not affect another.
        assert!(
            router.try_admit(&b).is_some(),
            "b should still be admittable"
        );
    }

    #[tokio::test]
    async fn global_cap_rejects_without_bumping_per_peer() {
        // Global cap of 2, with two permits held to keep the semaphore at 0.
        let router = make_router(2);
        let a = PeerId::random();
        let b = PeerId::random();

        let _p1 = router.try_admit(&a).expect("first slot");
        let _p2 = router.try_admit(&a).expect("second slot");

        // The per-peer increment for b runs *before* the global check, so
        // the global-rejection path is responsible for rolling it back.
        assert!(router.try_admit(&b).is_none(), "global cap should reject");
        assert_eq!(
            peer_count(&router, &b),
            0,
            "global rejection must roll back the speculative per-peer increment"
        );
    }

    #[tokio::test]
    async fn cooldown_short_circuits_before_per_peer_check() {
        // Force the peer into cooldown directly. The trigger path is covered
        // by the record_failure tests below; this test isolates the
        // *admission* behavior when cooldown is active.
        let router = make_router(8);
        let peer = PeerId::random();
        router.per_peer_failures.insert(
            peer,
            PeerRateState {
                failures: FAILURE_THRESHOLD,
                window_start: Instant::now(),
                cooldown_until: Some(Instant::now() + Duration::from_mins(1)),
                backoff: INITIAL_COOLDOWN * 2,
            },
        );

        assert!(router.try_admit(&peer).is_none(), "cooldown should reject");
        // The per-peer code path uses `entry().or_insert_with(...)`, which
        // creates the map entry on first touch even if the request is later
        // rolled back. Asserting absence proves cooldown short-circuited
        // *before* the per-peer check ran at all — a stronger claim than
        // "the counter ended up at zero" (which would also hold if the
        // per-peer path ran and rolled itself back).
        assert!(
            router.per_peer.get(&peer).is_none(),
            "cooldown must short-circuit before any per-peer state is touched"
        );
    }

    #[tokio::test]
    async fn record_failure_triggers_cooldown_at_threshold() {
        let router = make_router(8);
        let peer = PeerId::random();

        for _ in 0..FAILURE_THRESHOLD - 1 {
            router.record_failure(&peer);
        }
        let (_failures, cooldown_until, _backoff) =
            failure_state(&router, &peer).expect("entry created");
        assert!(
            cooldown_until.is_none(),
            "cooldown must not trigger below threshold"
        );

        let before = Instant::now();
        router.record_failure(&peer);
        let (_failures, cooldown_until, backoff) =
            failure_state(&router, &peer).expect("entry exists");
        let cooldown_until = cooldown_until.expect("cooldown engaged at threshold");
        // Order matters: sample `remaining` before `elapsed` so any time spent
        // between the two `Instant::now()` calls is captured by `elapsed`,
        // not lost from the sum.
        let remaining = cooldown_until.saturating_duration_since(Instant::now());
        let elapsed = before.elapsed();

        // cooldown_until ≈ now + INITIAL_COOLDOWN, with `elapsed` of slack.
        assert!(remaining <= INITIAL_COOLDOWN);
        assert!(
            remaining + elapsed >= INITIAL_COOLDOWN,
            "cooldown must be at least INITIAL_COOLDOWN, got remaining={remaining:?}"
        );
        // `backoff` is the *next* cooldown duration, already doubled.
        assert_eq!(backoff, INITIAL_COOLDOWN * 2);
    }

    #[tokio::test]
    async fn cooldown_doubles_on_retrigger() {
        let router = make_router(8);
        let peer = PeerId::random();

        for _ in 0..FAILURE_THRESHOLD {
            router.record_failure(&peer);
        }
        let (_, _, backoff_after_first) = failure_state(&router, &peer).expect("entry exists");
        assert_eq!(
            backoff_after_first,
            INITIAL_COOLDOWN * 2,
            "after first trigger, next-time backoff should be doubled"
        );

        // Simulate cooldown expiry. We can't fast-forward `Instant::now`, so
        // poke the state to mirror what try_admit's expiry branch does. This
        // binds the test to private fields — acceptable, but a clock
        // abstraction would let us drop the poke.
        {
            let mut entry = router.per_peer_failures.get_mut(&peer).unwrap();
            entry.cooldown_until = None;
            entry.failures = 0;
            entry.window_start = Instant::now();
        }

        let before = Instant::now();
        for _ in 0..FAILURE_THRESHOLD {
            router.record_failure(&peer);
        }
        let (_, cooldown_until, backoff) = failure_state(&router, &peer).expect("entry exists");
        // Sample `remaining` before `elapsed` so the time between the two
        // `Instant::now()` calls is captured by `elapsed`, not lost.
        let remaining = cooldown_until
            .expect("second cooldown engaged")
            .saturating_duration_since(Instant::now());
        let elapsed = before.elapsed();
        let expected = INITIAL_COOLDOWN * 2;
        assert!(remaining <= expected);
        assert!(
            remaining + elapsed >= expected,
            "second cooldown should be {expected:?}, got remaining={remaining:?}"
        );
        assert_eq!(
            backoff,
            INITIAL_COOLDOWN * 4,
            "backoff doubles again on the second trigger"
        );
    }

    #[tokio::test]
    async fn record_success_resets_failure_state() {
        let router = make_router(8);
        let peer = PeerId::random();

        for _ in 0..FAILURE_THRESHOLD {
            router.record_failure(&peer);
        }
        router.record_success(&peer);

        let (failures, cooldown_until, backoff) =
            failure_state(&router, &peer).expect("entry exists");
        assert_eq!(failures, 0, "success resets failure count");
        assert!(cooldown_until.is_none(), "success clears cooldown");
        assert_eq!(
            backoff, INITIAL_COOLDOWN,
            "success resets backoff so a recovered peer regains trust immediately"
        );
    }

    #[tokio::test]
    async fn classifies_client_abandonment_kinds_as_true() {
        // Speculative-retry clients abandon streams as a normal part of their
        // retry strategy — these kinds must NOT count toward the failure
        // threshold or healthy peers would get cooled down spuriously.
        let kinds = [
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionAborted,
        ];
        for kind in kinds {
            let direct = StreamError::Io(std::io::Error::new(kind, "test"));
            assert!(
                direct.is_client_abandonment(),
                "Io({kind:?}) should be client abandonment"
            );
            // Same kinds nested inside Frame::Io must classify identically;
            // the framing layer is just a wrapper, not a different signal.
            let nested = StreamError::Frame(FrameError::Io(std::io::Error::new(kind, "test")));
            assert!(
                nested.is_client_abandonment(),
                "Frame::Io({kind:?}) should be client abandonment"
            );
        }
    }

    #[tokio::test]
    async fn classifies_real_failures_as_not_abandonment() {
        // These all represent local faults or protocol violations — they
        // SHOULD count toward the failure threshold so a misbehaving peer
        // gets cooled down.
        let cases = [
            StreamError::Timeout,
            StreamError::UnknownMessageType,
            StreamError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, "test")),
            StreamError::Io(std::io::Error::other("test")),
            StreamError::Frame(FrameError::TooLarge(1_000_000)),
            // Frame::Io with a non-abandonment kind also stays a real failure.
            StreamError::Frame(FrameError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "test",
            ))),
        ];
        for err in cases {
            assert!(
                !err.is_client_abandonment(),
                "{err:?} must count as a real failure"
            );
        }
    }
}
