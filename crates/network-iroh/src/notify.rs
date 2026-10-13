//! Persistent notification streams, one per peer and class.
//!
//! Each `(peer, class)` pair gets a dedicated task that owns one
//! unidirectional stream on the connection to that peer and writes frames to
//! it in order. The stream's priority follows its class, so the connection
//! sends a queued consensus frame before any bulk data buffered for the same
//! peer, and a slow class never delays another.
//!
//! ## Failure recovery
//!
//! Notifications carry consensus traffic, and their emitters are fire and
//! forget: a dropped vote is never re-sent and can stall a view. So the task
//! retries in place. It retains a frame whose write failed, waits out the
//! shared backoff, opens a stream on whatever connection the peer has by
//! then, and sends it again; its queue stays intact across the reopen.
//! Receivers dedup notifications, so a write that reported failure after
//! reaching the peer is harmless. Only after [`MAX_CONSECUTIVE_FAILURES`]
//! straight failures does the task give up and drop its queue; from there
//! recovery belongs to the protocol layer.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hyperscale_metrics::record_libp2p_bandwidth;
use hyperscale_network::stream_backoff::StreamFailure;
use hyperscale_types::MessageClass;
use iroh::EndpointId;
use iroh::endpoint::SendStream;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::time::{Instant as TokioInstant, sleep, sleep_until};
use tracing::warn;

use crate::endpoint::IrohAdapter;
use crate::error::NetworkError;
use crate::framing;
use crate::peer_backoff::{self, BackoffState};
use crate::protocol::{STREAM_NOTIFY, class_priority};

/// Queue capacity per stream. Bounds memory and sheds load: a full queue
/// drops the new frame.
const STREAM_QUEUE_CAPACITY: usize = 256;

/// Consecutive open or write failures a task rides out, waiting the shared
/// backoff between attempts, before it gives up and drops its queue.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// The peer and class one stream serves.
type StreamKey = (EndpointId, MessageClass);

/// A message queued for one notification stream.
///
/// Carries pre-compressed data so compression happens once per message
/// rather than once per peer.
#[cfg_attr(test, derive(Debug))]
struct PendingFrame {
    type_id: &'static str,
    compressed_data: Vec<u8>,
    /// When the frame was enqueued. The task holds it until `queued_at +
    /// simulated latency`, so each frame leaves a fixed delay after it was
    /// produced without throttling the drain rate.
    queued_at: TokioInstant,
}

/// Manages the outbound notification streams.
pub struct NotifyPool {
    adapter: Arc<IrohAdapter>,
    /// Queue of each live stream task.
    streams: Arc<DashMap<StreamKey, mpsc::Sender<PendingFrame>>>,
    /// Backoff of each stream that failed to open or write.
    backoff: Arc<DashMap<StreamKey, BackoffState>>,
    tokio_handle: Handle,
    /// Per-frame outbound delay (`Duration::ZERO` in production).
    latency: Duration,
}

impl NotifyPool {
    pub fn new(adapter: Arc<IrohAdapter>, tokio_handle: Handle, latency: Duration) -> Self {
        Self {
            adapter,
            streams: Arc::new(DashMap::new()),
            backoff: Arc::new(DashMap::new()),
            tokio_handle,
            latency,
        }
    }

    /// Queue a pre-compressed notification frame of `class` for `peer`.
    ///
    /// Non-blocking: the frame joins the stream task's queue, spawning the
    /// task if none is live.
    pub fn send(
        &self,
        peer: EndpointId,
        class: MessageClass,
        type_id: &'static str,
        compressed_data: Vec<u8>,
    ) {
        let key = (peer, class);
        let frame = PendingFrame {
            type_id,
            compressed_data,
            queued_at: TokioInstant::now(),
        };
        if let Err(frame) = try_enqueue_existing(&self.streams, &key, frame) {
            self.spawn_stream(key, frame);
        }
    }

    fn spawn_stream(&self, key: StreamKey, initial_frame: PendingFrame) {
        let (frame_tx, frame_rx) = mpsc::channel(STREAM_QUEUE_CAPACITY);
        let _ = frame_tx.try_send(initial_frame);
        self.streams.insert(key, frame_tx);

        let streams = Arc::clone(&self.streams);
        let backoff = Arc::clone(&self.backoff);
        let adapter = Arc::clone(&self.adapter);
        let latency = self.latency;
        self.tokio_handle.spawn(async move {
            run_stream(key, frame_rx, &adapter, &backoff, latency).await;
            streams.remove(&key);
        });
    }
}

/// Open the stream for `key` and mark it as a notification stream.
async fn open(adapter: &IrohAdapter, key: StreamKey) -> Result<SendStream, NetworkError> {
    let (peer, class) = key;
    let mut stream = adapter.open_uni(peer).await?;
    // The stream is ours alone and open, so setting its priority cannot
    // fail.
    let _ = stream.set_priority(class_priority(class));
    stream
        .write_all(&[STREAM_NOTIFY])
        .await
        .map_err(|e| NetworkError::StreamIo(io::Error::from(e).to_string()))?;
    Ok(stream)
}

/// Stream task: write queued frames in order, reopening in place on
/// failure, until the queue's senders are gone or the failure budget is
/// spent.
async fn run_stream(
    key: StreamKey,
    mut frame_rx: mpsc::Receiver<PendingFrame>,
    adapter: &IrohAdapter,
    backoff: &DashMap<StreamKey, BackoffState>,
    latency: Duration,
) {
    let (peer, class) = key;
    let mut failures: u32 = 0;
    // A frame whose write failed, retained across the reopen.
    let mut retained: Option<PendingFrame> = None;

    'reopen: loop {
        if let Some(state) = backoff.get(&key) {
            let next_attempt = state.next_attempt();
            drop(state);
            let now = Instant::now();
            if now < next_attempt {
                sleep(next_attempt - now).await;
            }
        }

        let mut stream = match open(adapter, key).await {
            Ok(stream) => stream,
            Err(error) => {
                peer_backoff::apply_backoff(backoff, &key, StreamFailure::Transient);
                failures += 1;
                if failures >= MAX_CONSECUTIVE_FAILURES {
                    warn!(
                        peer = %peer.fmt_short(),
                        class = class.as_str(),
                        %error,
                        "Notify stream cannot open; dropping queued frames"
                    );
                    return;
                }
                continue 'reopen;
            }
        };
        backoff.remove(&key);

        loop {
            let frame = if let Some(frame) = retained.take() {
                frame
            } else {
                let Some(frame) = frame_rx.recv().await else {
                    let _ = stream.finish();
                    return;
                };
                frame
            };
            if !latency.is_zero() {
                sleep_until(frame.queued_at + latency).await;
            }
            match framing::write_precompressed_typed_frame(
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
                Err(error) => {
                    peer_backoff::apply_backoff(backoff, &key, StreamFailure::Transient);
                    failures += 1;
                    if failures >= MAX_CONSECUTIVE_FAILURES {
                        warn!(
                            peer = %peer.fmt_short(),
                            class = class.as_str(),
                            %error,
                            "Notify stream keeps failing; dropping queued frames"
                        );
                        return;
                    }
                    retained = Some(frame);
                    continue 'reopen;
                }
            }
        }
    }
}

/// Try to enqueue `frame` onto the live stream task for `key`.
///
/// Returns `Ok(())` when the frame was either queued or deliberately dropped
/// (queue full: bounded memory at the cost of frame loss, which is
/// acceptable for notifications). Returns `Err(frame)` when there is no live
/// task, handing the frame back so the caller can spawn one, and removes the
/// dead task's entry.
fn try_enqueue_existing(
    streams: &DashMap<StreamKey, mpsc::Sender<PendingFrame>>,
    key: &StreamKey,
    frame: PendingFrame,
) -> Result<(), PendingFrame> {
    let Some(queue) = streams.get(key) else {
        return Err(frame);
    };
    match queue.try_send(frame) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            warn!(
                peer = %key.0.fmt_short(),
                class = key.1.as_str(),
                "Notification queue full, dropping frame"
            );
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(frame_back)) => {
            drop(queue);
            streams.remove(key);
            Err(frame_back)
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    fn key() -> StreamKey {
        (SecretKey::generate().public(), MessageClass::Consensus)
    }

    fn make_frame(tag: u8) -> PendingFrame {
        PendingFrame {
            type_id: "test.notify",
            compressed_data: vec![tag],
            queued_at: TokioInstant::now(),
        }
    }

    fn install(
        streams: &DashMap<StreamKey, mpsc::Sender<PendingFrame>>,
        key: StreamKey,
        capacity: usize,
    ) -> mpsc::Receiver<PendingFrame> {
        let (tx, rx) = mpsc::channel(capacity);
        streams.insert(key, tx);
        rx
    }

    #[tokio::test]
    async fn a_frame_reaches_the_live_task_of_its_peer_and_class() {
        let streams = DashMap::new();
        let key = key();
        let mut rx = install(&streams, key, 4);

        assert!(try_enqueue_existing(&streams, &key, make_frame(1)).is_ok());
        assert_eq!(rx.try_recv().unwrap().compressed_data, vec![1]);

        // Another class to the same peer is another stream.
        let other_class = (key.0, MessageClass::Bulk);
        assert!(try_enqueue_existing(&streams, &other_class, make_frame(2)).is_err());
    }

    #[tokio::test]
    async fn a_full_queue_drops_the_new_frame_and_keeps_its_task() {
        let streams = DashMap::new();
        let key = key();
        let mut rx = install(&streams, key, 1);
        assert!(try_enqueue_existing(&streams, &key, make_frame(0xAA)).is_ok());

        assert!(
            try_enqueue_existing(&streams, &key, make_frame(0xBB)).is_ok(),
            "a full queue is handled, not a signal to respawn"
        );
        assert!(streams.contains_key(&key));
        assert_eq!(rx.try_recv().unwrap().compressed_data, vec![0xAA]);
        assert!(rx.try_recv().is_err(), "the dropped frame was not queued");
    }

    #[tokio::test]
    async fn a_dead_task_hands_the_frame_back_and_is_evicted() {
        let streams = DashMap::new();
        let key = key();
        drop(install(&streams, key, 4));

        let returned = try_enqueue_existing(&streams, &key, make_frame(0xCC))
            .expect_err("a dead task signals respawn");
        assert_eq!(returned.compressed_data, vec![0xCC]);
        assert!(!streams.contains_key(&key));
    }
}
