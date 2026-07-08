//! Persistent per-peer notification stream pool.
//!
//! Instead of opening a fresh libp2p stream for every notification (which
//! causes `Stopped(0)` connection resets and vote/header loss), this module
//! maintains one long-lived stream per peer via an actor-per-peer pattern.
//!
//! Each peer gets a dedicated tokio task that owns the `Stream` and receives
//! frames via an `mpsc` channel. This naturally serializes writes and avoids
//! `Mutex<Stream>` across await points.
//!
//! ## Failure recovery
//!
//! Notifications carry consensus traffic — beacon PC votes among them — and
//! a beacon committee spanning shards may exchange messages only at epoch
//! cadence, long enough for the underlying QUIC connection to idle out. The
//! first write after such a gap fails at the connection layer; dropping that
//! frame loses a vote that is never re-sent (the emitters are fire-and-forget)
//! and can stall an SPC view outright. So the actor retries in place: it
//! retains the failed frame, waits out the shared reconnection backoff,
//! reopens the stream, and re-sends — its queue stays intact across the
//! reconnect. Receivers dedup notifications (votes by signer and position,
//! headers by hash), so a write that reported failure after reaching the
//! peer is harmless. Only after [`MAX_CONSECUTIVE_FAILURES`] straight
//! open/write failures does the actor give up and drop its queue; from
//! there recovery belongs to the protocol layer.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures::AsyncWriteExt;
use hyperscale_metrics::record_libp2p_bandwidth;
use libp2p::PeerId;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::time::{Instant as TokioInstant, sleep, sleep_until};
use tracing::warn;

use crate::adapter::Libp2pAdapter;
use crate::peer_backoff::{self, BackoffState};
use crate::stream_framing;

/// Channel capacity per peer. Bounds memory usage and provides backpressure.
/// At ~1KB per notification, 256 frames ≈ 256KB buffer per peer.
const PEER_CHANNEL_CAPACITY: usize = 256;

/// Consecutive open/write failures an actor rides out (waiting the shared
/// backoff between attempts) before it gives up and drops its queue. Five
/// attempts on the 100ms-doubling series spans roughly ten seconds — enough
/// to bridge an idled-out connection's redial, short enough that a truly
/// unreachable peer doesn't pin frames indefinitely.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// A message queued for sending on a persistent notification stream.
///
/// Carries pre-compressed data so that compression happens once per message
/// (in [`Libp2pNetwork::notify`]) rather than once per peer.
#[cfg_attr(test, derive(Debug))]
struct PendingFrame {
    type_id: &'static str,
    compressed_data: Vec<u8>,
    /// When the frame was enqueued. The actor holds it until
    /// `queued_at + simulated latency`, so each frame leaves the wire a
    /// fixed delay after it was produced — modelling propagation delay
    /// without throttling drain rate (a burst still flushes back to back
    /// once the delay elapses, so the bounded channel never backs up).
    queued_at: TokioInstant,
}

/// Handle to a per-peer stream actor. Dropping the sender closes the channel,
/// which causes the actor to shut down gracefully.
struct PeerStreamActor {
    frame_tx: mpsc::Sender<PendingFrame>,
}

/// Manages persistent outbound notification streams, one per peer.
///
/// When `send()` is called, it looks up or creates a stream actor for the
/// target peer and sends the frame through the actor's channel. The actor
/// task owns the actual `libp2p::Stream` and writes frames sequentially.
pub struct NotifyStreamPool {
    adapter: Arc<Libp2pAdapter>,
    /// Per-peer stream actors. Key = `PeerId`, Value = actor handle.
    peers: Arc<DashMap<PeerId, PeerStreamActor>>,
    /// Backoff tracking for reconnection after failures.
    backoff: Arc<DashMap<PeerId, BackoffState>>,
    /// Tokio runtime handle for spawning actor tasks.
    tokio_handle: Handle,
    /// Per-frame outbound delay (`Duration::ZERO` in production).
    latency: Duration,
}

impl NotifyStreamPool {
    pub fn new(adapter: Arc<Libp2pAdapter>, tokio_handle: Handle, latency: Duration) -> Self {
        Self {
            adapter,
            peers: Arc::new(DashMap::new()),
            backoff: Arc::new(DashMap::new()),
            tokio_handle,
            latency,
        }
    }

    /// Send a pre-compressed notification frame to a peer.
    ///
    /// The caller is responsible for SBOR-encoding and LZ4-compressing the
    /// payload once; this method fans out the already-compressed bytes to
    /// each peer's stream actor without redundant compression.
    ///
    /// If a persistent stream actor exists and is healthy, the frame is queued
    /// (non-blocking fast path). If no actor exists or the existing one is dead,
    /// a new actor is spawned (subject to backoff).
    pub fn send(&self, peer_id: PeerId, type_id: &'static str, compressed_data: Vec<u8>) {
        let frame = PendingFrame {
            type_id,
            compressed_data,
            queued_at: TokioInstant::now(),
        };

        if let Err(frame_back) = try_enqueue_existing(&self.peers, &peer_id, frame) {
            // No live actor — spawn one (subject to backoff).
            self.spawn_actor(peer_id, frame_back);
        }
    }

    /// Spawn a new stream actor for a peer. The actor itself waits out any
    /// active reconnection backoff before dialing, so frames sent during
    /// the backoff window queue in its channel instead of being dropped.
    fn spawn_actor(&self, peer_id: PeerId, initial_frame: PendingFrame) {
        let (frame_tx, frame_rx) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        // Enqueue the initial frame into the new channel.
        let _ = frame_tx.try_send(initial_frame);

        self.peers.insert(peer_id, PeerStreamActor { frame_tx });

        let peers = self.peers.clone();
        let backoff = self.backoff.clone();
        let adapter = self.adapter.clone();
        let latency = self.latency;

        self.tokio_handle.spawn(async move {
            Self::run_stream_actor(peer_id, frame_rx, adapter, peers, backoff, latency).await;
        });
    }

    /// Actor task: opens a persistent stream and writes queued frames,
    /// reconnecting in place on failure.
    ///
    /// An open or write failure escalates the shared backoff and loops back
    /// to reopen — the failed frame is retained for re-send and the channel
    /// (with any queued frames) survives the reconnect. After
    /// [`MAX_CONSECUTIVE_FAILURES`] straight failures the actor drops its
    /// queue and exits; the next `send()` spawns a successor that waits out
    /// whatever backoff remains.
    async fn run_stream_actor(
        peer_id: PeerId,
        mut frame_rx: mpsc::Receiver<PendingFrame>,
        adapter: Arc<Libp2pAdapter>,
        peers: Arc<DashMap<PeerId, PeerStreamActor>>,
        backoff_map: Arc<DashMap<PeerId, BackoffState>>,
        latency: Duration,
    ) {
        let mut failures: u32 = 0;
        // A frame whose write failed, retained across the reconnect.
        let mut retained: Option<PendingFrame> = None;

        'reconnect: loop {
            // Wait out any active backoff before dialing.
            if let Some(state) = backoff_map.get(&peer_id) {
                let next_attempt = state.next_attempt;
                drop(state);
                let now = Instant::now();
                if now < next_attempt {
                    sleep(next_attempt - now).await;
                }
            }

            let mut stream = match adapter.open_notify_stream(peer_id).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(peer = %peer_id, error = ?e, "Failed to open persistent notify stream");
                    peer_backoff::apply_backoff(&backoff_map, &peer_id);
                    failures += 1;
                    if failures >= MAX_CONSECUTIVE_FAILURES {
                        break 'reconnect;
                    }
                    continue 'reconnect;
                }
            };

            // Clear backoff on successful connection.
            backoff_map.remove(&peer_id);

            loop {
                let frame = if let Some(frame) = retained.take() {
                    frame
                } else {
                    let Some(frame) = frame_rx.recv().await else {
                        // Channel closed (Libp2pNetwork dropped or pool
                        // shutdown). Graceful close.
                        let _ = stream.close().await;
                        peers.remove(&peer_id);
                        return;
                    };
                    frame
                };
                if !latency.is_zero() {
                    sleep_until(frame.queued_at + latency).await;
                }
                match stream_framing::write_precompressed_typed_frame_no_close(
                    &mut stream,
                    frame.type_id,
                    &frame.compressed_data,
                )
                .await
                {
                    Ok(wire_bytes) => {
                        record_libp2p_bandwidth(0, wire_bytes as u64);
                        failures = 0;
                    }
                    Err(e) => {
                        warn!(
                            peer = %peer_id,
                            error = ?e,
                            "Persistent notify stream write failed — reconnecting"
                        );
                        peer_backoff::apply_backoff(&backoff_map, &peer_id);
                        failures += 1;
                        if failures >= MAX_CONSECUTIVE_FAILURES {
                            break 'reconnect;
                        }
                        retained = Some(frame);
                        continue 'reconnect;
                    }
                }
            }
        }

        warn!(
            peer = %peer_id,
            failures,
            "Notify stream actor giving up — dropping queued frames"
        );
        peers.remove(&peer_id);
    }
}

/// Try to enqueue `frame` onto the existing actor for `peer_id`.
///
/// Returns `Ok(())` when the frame was either sent or deliberately dropped
/// (channel full — bounded-channel backpressure protects memory at the cost
/// of frame loss, which is acceptable for notifications). Returns
/// `Err(frame)` when there is no live actor, handing the frame back so the
/// caller can spawn one. Removes the dead actor's entry as a side effect.
fn try_enqueue_existing(
    peers: &DashMap<PeerId, PeerStreamActor>,
    peer_id: &PeerId,
    frame: PendingFrame,
) -> Result<(), PendingFrame> {
    let Some(actor) = peers.get(peer_id) else {
        return Err(frame);
    };
    match actor.frame_tx.try_send(frame) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            warn!(peer = %peer_id, "Notification channel full, dropping frame");
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(frame_back)) => {
            drop(actor);
            peers.remove(peer_id);
            Err(frame_back)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(tag: u8) -> PendingFrame {
        PendingFrame {
            type_id: "test.notify",
            compressed_data: vec![tag],
            queued_at: TokioInstant::now(),
        }
    }

    fn install_actor(
        peers: &DashMap<PeerId, PeerStreamActor>,
        peer: PeerId,
        capacity: usize,
    ) -> mpsc::Receiver<PendingFrame> {
        let (tx, rx) = mpsc::channel(capacity);
        peers.insert(peer, PeerStreamActor { frame_tx: tx });
        rx
    }

    #[tokio::test]
    async fn try_enqueue_delivers_to_live_actor() {
        let peers = DashMap::new();
        let peer = PeerId::random();
        let mut rx = install_actor(&peers, peer, 4);

        let result = try_enqueue_existing(&peers, &peer, make_frame(1));
        assert!(result.is_ok());

        let received = rx.try_recv().expect("frame delivered to actor channel");
        assert_eq!(received.compressed_data, vec![1]);
        assert!(peers.contains_key(&peer), "live actor entry preserved");
    }

    #[tokio::test]
    async fn try_enqueue_drops_frame_when_channel_full() {
        // Capacity 1, pre-fill, then attempt to send — frame must be dropped
        // (no panic, no respawn) since notifications prefer loss to unbounded
        // memory growth.
        let peers = DashMap::new();
        let peer = PeerId::random();
        let mut rx = install_actor(&peers, peer, 1);
        let actor_tx = peers.get(&peer).unwrap().frame_tx.clone();
        actor_tx.try_send(make_frame(0xAA)).expect("prime channel");

        let result = try_enqueue_existing(&peers, &peer, make_frame(0xBB));
        assert!(
            result.is_ok(),
            "full channel must be reported as handled, not as a respawn signal"
        );
        assert!(
            peers.contains_key(&peer),
            "actor entry must survive a dropped frame"
        );

        // Only the priming frame is in the channel — the new one was dropped.
        let first = rx.try_recv().expect("priming frame still queued");
        assert_eq!(first.compressed_data, vec![0xAA]);
        assert!(rx.try_recv().is_err(), "dropped frame must not be queued");
    }

    #[tokio::test]
    async fn try_enqueue_returns_frame_and_evicts_when_actor_dead() {
        // Closing the receiver makes the sender's try_send return Closed.
        let peers = DashMap::new();
        let peer = PeerId::random();
        let rx = install_actor(&peers, peer, 4);
        drop(rx);

        let result = try_enqueue_existing(&peers, &peer, make_frame(0xCC));
        match result {
            Err(returned) => assert_eq!(
                returned.compressed_data,
                vec![0xCC],
                "exact frame must be handed back so the spawn path can re-queue it"
            ),
            Ok(()) => panic!("dead actor must signal respawn via Err"),
        }
        assert!(
            !peers.contains_key(&peer),
            "dead actor entry must be evicted so the next send spawns fresh"
        );
    }

    #[tokio::test]
    async fn try_enqueue_returns_frame_when_no_actor_exists() {
        let peers = DashMap::new();
        let peer = PeerId::random();

        let result = try_enqueue_existing(&peers, &peer, make_frame(0xDD));
        match result {
            Err(returned) => assert_eq!(returned.compressed_data, vec![0xDD]),
            Ok(()) => panic!("absent actor must signal spawn via Err"),
        }
        assert!(!peers.contains_key(&peer), "no actor entry was created");
    }
}
