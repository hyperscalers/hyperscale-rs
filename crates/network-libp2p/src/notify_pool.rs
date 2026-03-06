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
//! If a persistent stream fails, the actor exits and applies exponential
//! backoff. The next `send()` call spawns a new actor after the backoff
//! period elapses.

use crate::adapter::Libp2pAdapter;
use crate::stream_framing;
use dashmap::DashMap;
use futures::AsyncWriteExt;
use hyperscale_metrics as metrics;
use libp2p::PeerId;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Initial reconnection backoff after a stream failure.
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Maximum reconnection backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Backoff multiplier for exponential backoff.
const BACKOFF_MULTIPLIER: u32 = 2;

/// Channel capacity per peer. Bounds memory usage and provides backpressure.
/// At ~1KB per notification, 256 frames ≈ 256KB buffer per peer.
const PEER_CHANNEL_CAPACITY: usize = 256;

/// A message queued for sending on a persistent notification stream.
///
/// Carries pre-compressed data so that compression happens once per message
/// (in [`ProdNetwork::notify`]) rather than once per peer.
struct PendingFrame {
    type_id: &'static str,
    compressed_data: Vec<u8>,
}

/// Exponential backoff state for a peer after stream failure.
struct BackoffState {
    next_attempt: Instant,
    current_backoff: Duration,
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
pub(crate) struct NotifyStreamPool {
    adapter: Arc<Libp2pAdapter>,
    /// Per-peer stream actors. Key = PeerId, Value = actor handle.
    peers: Arc<DashMap<PeerId, PeerStreamActor>>,
    /// Backoff tracking for reconnection after failures.
    backoff: Arc<DashMap<PeerId, BackoffState>>,
    /// Tokio runtime handle for spawning actor tasks.
    tokio_handle: tokio::runtime::Handle,
}

impl NotifyStreamPool {
    pub fn new(adapter: Arc<Libp2pAdapter>, tokio_handle: tokio::runtime::Handle) -> Self {
        Self {
            adapter,
            peers: Arc::new(DashMap::new()),
            backoff: Arc::new(DashMap::new()),
            tokio_handle,
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
        };

        // Fast path: try to send on existing actor's channel.
        if let Some(actor) = self.peers.get(&peer_id) {
            match actor.frame_tx.try_send(frame) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(peer = %peer_id, "Notification channel full, dropping frame");
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(frame_back)) => {
                    // Actor task is dead. Drop the DashMap ref before removing.
                    drop(actor);
                    self.peers.remove(&peer_id);
                    // Fall through to spawn a new actor with the recovered frame.
                    self.spawn_actor(peer_id, frame_back);
                    return;
                }
            }
        }

        // No actor exists — spawn one (subject to backoff).
        self.spawn_actor(peer_id, frame);
    }

    /// Spawn a new stream actor for a peer, subject to backoff.
    fn spawn_actor(&self, peer_id: PeerId, initial_frame: PendingFrame) {
        // Check backoff before creating a new stream.
        if let Some(state) = self.backoff.get(&peer_id) {
            if Instant::now() < state.next_attempt {
                debug!(peer = %peer_id, "Skipping notify: in backoff period");
                return;
            }
        }

        let (frame_tx, frame_rx) = mpsc::channel(PEER_CHANNEL_CAPACITY);
        // Enqueue the initial frame into the new channel.
        let _ = frame_tx.try_send(initial_frame);

        self.peers.insert(peer_id, PeerStreamActor { frame_tx });

        let peers = self.peers.clone();
        let backoff = self.backoff.clone();
        let adapter = self.adapter.clone();

        self.tokio_handle.spawn(async move {
            Self::run_stream_actor(peer_id, frame_rx, adapter, peers, backoff).await;
        });
    }

    /// Actor task: opens a persistent stream and writes queued frames.
    ///
    /// On stream failure, applies backoff and exits. The next `send()` call
    /// will detect the dead channel and spawn a new actor.
    async fn run_stream_actor(
        peer_id: PeerId,
        mut frame_rx: mpsc::Receiver<PendingFrame>,
        adapter: Arc<Libp2pAdapter>,
        peers: Arc<DashMap<PeerId, PeerStreamActor>>,
        backoff_map: Arc<DashMap<PeerId, BackoffState>>,
    ) {
        // Open the persistent stream.
        let mut stream = match adapter.open_notify_stream(peer_id).await {
            Ok(s) => s,
            Err(e) => {
                debug!(peer = %peer_id, error = ?e, "Failed to open persistent notify stream");
                Self::apply_backoff(&backoff_map, &peer_id);
                peers.remove(&peer_id);
                return;
            }
        };

        // Clear backoff on successful connection.
        backoff_map.remove(&peer_id);

        // Read frames from channel and write to stream.
        while let Some(frame) = frame_rx.recv().await {
            match stream_framing::write_precompressed_typed_frame_no_close(
                &mut stream,
                frame.type_id,
                &frame.compressed_data,
            )
            .await
            {
                Ok(wire_bytes) => {
                    metrics::record_libp2p_bandwidth(0, wire_bytes as u64);
                }
                Err(e) => {
                    debug!(
                        peer = %peer_id,
                        error = ?e,
                        "Persistent notify stream write failed"
                    );
                    Self::apply_backoff(&backoff_map, &peer_id);
                    peers.remove(&peer_id);
                    return;
                }
            }
        }

        // Channel closed (ProdNetwork dropped or pool shutdown). Graceful close.
        let _ = stream.close().await;
        peers.remove(&peer_id);
    }

    /// Apply exponential backoff for a peer after a stream failure.
    fn apply_backoff(backoff_map: &DashMap<PeerId, BackoffState>, peer_id: &PeerId) {
        let current_backoff = backoff_map
            .get(peer_id)
            .map(|state| (state.current_backoff * BACKOFF_MULTIPLIER).min(MAX_BACKOFF))
            .unwrap_or(INITIAL_BACKOFF);

        backoff_map.insert(
            *peer_id,
            BackoffState {
                next_attempt: Instant::now() + current_backoff,
                current_backoff,
            },
        );
    }
}
