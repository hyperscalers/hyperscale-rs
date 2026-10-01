//! Request manager with intelligent retry and peer selection.
//!
//! The key insight: under packet loss, a failed request doesn't mean the peer
//! is bad—it means the network dropped packets. Retrying the SAME peer first
//! is often correct because packet loss is probabilistic.
//!
//! # Design Philosophy
//!
//! This module implements **request-centric** retry logic, in contrast to the
//! traditional **peer-centric** approach:
//!
//! - **Peer-centric**: Timeout → blame peer → cooldown → try next peer
//! - **Request-centric**: Timeout → retry same peer → rotate after threshold
//!
//! The request-centric approach works better under packet loss because:
//! 1. Packet loss is probabilistic—the peer that timed out might succeed on retry
//! 2. Rotating too quickly exhausts all peers and triggers "desperation mode"
//! 3. Weighted selection ensures unhealthy peers still get occasional chances
//!
//! # Example
//!
//! ```ignore
//! let manager = RequestManager::new(adapter.clone(), RequestManagerConfig::default());
//!
//! // Send a request with automatic retry
//! match manager.request(&peers, None, "block.request".into(), "block.request", wire_bytes, MessageClass::Recovery).await {
//!     Ok((peer, response)) => { /* success */ }
//!     Err(RequestError::Exhausted { attempts }) => { /* all retries failed */ }
//!     Err(RequestError::NoPeers) => { /* no peers available */ }
//! }
//! ```

mod concurrency;
mod retry;
mod stream;

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hyperscale_network::retry::{PeerHealthBook, RetryConfig, uses_relaxed_retry};
use hyperscale_types::{MessageClass, ShardId};
use libp2p::PeerId;
use parking_lot::Mutex;
use thiserror::Error;

use crate::adapter::NetworkError;
use crate::request_pool::RequestPool;

/// Errors from request operations.
#[derive(Debug, Error)]
pub enum RequestError {
    /// All retry attempts exhausted.
    #[error("request exhausted after {attempts} attempts")]
    Exhausted { attempts: u32 },

    /// No peers available to send to.
    #[error("no peers available")]
    NoPeers,

    /// Network-level error (non-retryable).
    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    /// Network is shutting down.
    #[error("network shutdown")]
    Shutdown,
}

/// Whether a class is in the cross-shard reservation tier.
///
/// `CrossShardProgress` traffic (provisions / EC fallback fetches) is
/// bounded by `config.cross_shard_max_concurrent` so a cross-shard fetch
/// storm during topology churn cannot starve the shard consensus hot path
/// (`Consensus`, `BlockCompletion`).
#[must_use]
pub const fn is_cross_shard(class: MessageClass) -> bool {
    matches!(class, MessageClass::CrossShardProgress)
}

#[cfg(test)]
mod retry_regime_tests {
    use hyperscale_types::MessageClass;

    use super::uses_relaxed_retry;

    #[test]
    fn consensus_uses_tight_retry() {
        assert!(!uses_relaxed_retry(MessageClass::Consensus));
    }

    #[test]
    fn block_completion_uses_tight_retry() {
        assert!(!uses_relaxed_retry(MessageClass::BlockCompletion));
    }

    #[test]
    fn cross_shard_progress_uses_tight_retry() {
        assert!(!uses_relaxed_retry(MessageClass::CrossShardProgress));
    }

    #[test]
    fn recovery_uses_relaxed_retry() {
        assert!(uses_relaxed_retry(MessageClass::Recovery));
    }

    #[test]
    fn bulk_uses_relaxed_retry() {
        assert!(uses_relaxed_retry(MessageClass::Bulk));
    }
}

/// Configuration for the request manager.
#[derive(Debug, Clone)]
pub struct RequestManagerConfig {
    /// Maximum total concurrent requests across all peers.
    pub max_concurrent: usize,

    /// Retry budget and backoff shape of each request.
    pub retry: RetryConfig,

    /// Cap on concurrent in-flight requests in the *sheddable* classes
    /// (`Recovery` + `Bulk`). Counted as a subset of `max_concurrent` —
    /// prevents a flood of catchup / DA-backfill fetches from filling the
    /// global pool and starving the hot path.
    pub sheddable_max_concurrent: usize,

    /// Cap on concurrent in-flight requests in the `CrossShardProgress`
    /// class. Counted as a subset of `max_concurrent` — prevents a
    /// cross-shard fetch storm (provisions / EC fallback during topology
    /// churn) from filling the global pool and starving the shard consensus hot path
    /// (`Consensus`, `BlockCompletion`). The hot path is therefore
    /// guaranteed `max_concurrent - cross_shard_max_concurrent -
    /// sheddable_max_concurrent` slots regardless of cross-shard or
    /// sheddable load.
    pub cross_shard_max_concurrent: usize,
}

impl Default for RequestManagerConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 128,
            retry: RetryConfig::default(),
            // 32/128 leaves 96 slots for hot-path + cross-shard classes
            // under any sheddable load — sized to absorb catchup / DA
            // bursts without blocking pending-block or cross-shard fetches.
            sheddable_max_concurrent: 32,
            // 48/128 paired with sheddable_max=32 reserves
            // 48 = 128 - 48 - 32 slots for the shard consensus hot path. Sized so a
            // burst of cross-shard fallback fetches can run in parallel
            // rather than serialising on a tight cap.
            cross_shard_max_concurrent: 48,
        }
    }
}

/// Request manager with intelligent retry and peer selection.
///
/// Provides:
/// - Request-centric retry logic (same peer first, then rotate)
/// - Weighted peer selection based on health metrics
/// - Per-class admission caps (sheddable / cross-shard subset reservations)
/// - Exponential backoff between retries
///
/// Actual stream I/O is delegated to a shared
/// [`RequestStreamPool`](crate::request_pool::RequestStreamPool), which
/// maintains one persistent stream per peer.
pub struct RequestManager {
    pool: Arc<dyn RequestPool>,
    config: RequestManagerConfig,
    /// Peer health across every request; never held across an await.
    health: Mutex<PeerHealthBook<PeerId>>,
    /// Origin of the clock the health book reads.
    origin: Instant,
    /// Current in-flight request count.
    in_flight: AtomicUsize,
    /// Subset of `in_flight` whose class is `Recovery` or `Bulk`. Capped
    /// independently by `config.sheddable_max_concurrent` so catchup /
    /// DA-backfill bursts can't starve the hot-path classes.
    sheddable_in_flight: AtomicUsize,
    /// Subset of `in_flight` whose class is `CrossShardProgress`. Capped
    /// independently by `config.cross_shard_max_concurrent` so cross-shard
    /// fetch storms can't starve the shard consensus hot path.
    cross_shard_in_flight: AtomicUsize,
    /// Per-class in-flight counters used to drive the
    /// `request_slots_in_flight{class}` gauge. Indexed by class
    /// discriminant (0..=4). Sum equals `in_flight`.
    per_class_in_flight: [AtomicUsize; 5],
}

impl RequestManager {
    /// Create a new request manager.
    ///
    /// `pool` is taken as a trait object so tests can substitute a
    /// deterministic mock; production callers pass `Arc<RequestStreamPool>`,
    /// which coerces automatically.
    #[must_use]
    pub fn new(pool: Arc<dyn RequestPool>, config: RequestManagerConfig) -> Self {
        Self {
            pool,
            health: Mutex::new(PeerHealthBook::default()),
            origin: Instant::now(),
            in_flight: AtomicUsize::new(0),
            sheddable_in_flight: AtomicUsize::new(0),
            cross_shard_in_flight: AtomicUsize::new(0),
            per_class_in_flight: [
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            ],
            config,
        }
    }

    /// Map a `MessageClass` onto the index used by `per_class_in_flight`.
    /// Mirrors the enum discriminant order in `crates/types/src/network.rs`.
    #[inline]
    pub(super) const fn class_index(class: MessageClass) -> usize {
        match class {
            MessageClass::Consensus => 0,
            MessageClass::BlockCompletion => 1,
            MessageClass::CrossShardProgress => 2,
            MessageClass::Recovery => 3,
            MessageClass::Bulk => 4,
        }
    }

    /// The health book's clock.
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    /// Send a request with automatic retry and peer failover.
    ///
    /// # Arguments
    ///
    /// * `peers` - Candidate peer list (from topology/committee)
    /// * `preferred_peer` - If provided and in the list, try this peer first
    /// * `request_desc` - Description for logging (e.g., "block.request")
    /// * `type_id` - Message type identifier for the typed frame header
    /// * `payload_data` - HBOR-encoded request payload (compressed by transport)
    /// * `class` - Message class (drives timeout and retry aggressiveness)
    ///
    /// # Returns
    ///
    /// The responding peer's ID and the response payload.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] when retries are exhausted, the request times out,
    /// or no peer in `peers` is reachable.
    #[allow(clippy::too_many_arguments)] // single retry/peer-rotation entry point
    pub async fn request(
        &self,
        peers: &[PeerId],
        preferred_peer: Option<PeerId>,
        shard: ShardId,
        request_desc: String,
        type_id: &'static str,
        payload_data: Vec<u8>,
        class: MessageClass,
    ) -> Result<(PeerId, Bytes), RequestError> {
        self.acquire_slot(class).await?;

        let result = self
            .request_inner(
                peers,
                preferred_peer,
                shard,
                &request_desc,
                type_id,
                &payload_data,
                class,
            )
            .await;

        self.release_slot(class);

        result
    }

    /// Count an answer the caller rejected against the peer that gave it.
    pub(crate) fn record_rejected(&self, peer: PeerId) {
        self.health.lock().record_rejected(peer);
    }
}
