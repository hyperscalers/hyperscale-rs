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
//! // Send a request with automatic retry (opaque bytes)
//! let data = frame_request("block.request", &sbor_bytes);
//! match manager.request(&peers, None, "block.request".into(), data, RequestPriority::Background).await {
//!     Ok((peer, response)) => { /* success */ }
//!     Err(RequestError::Exhausted { attempts }) => { /* all retries failed */ }
//!     Err(RequestError::NoPeers) => { /* no peers available */ }
//! }
//! ```

mod concurrency;
mod retry;
mod stream;
mod timeout;

use crate::adapter::{Libp2pAdapter, NetworkError};
use crate::peer_health::{PeerHealthConfig, PeerHealthTracker};
use bytes::Bytes;
use libp2p::PeerId;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// Maximum timeout for stream operations.
const MAX_STREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum timeout for stream operations (floor for RTT-based calculation).
const MIN_STREAM_TIMEOUT: Duration = Duration::from_millis(500);

/// Default timeout for stream operations when no RTT data is available.
/// Based on default RTT of 100ms × 5 = 500ms, but we use 1s to be safe for cold start.
const DEFAULT_STREAM_TIMEOUT: Duration = Duration::from_secs(1);

/// Multiplier for RTT to compute stream timeout.
/// Timeout = RTT * multiplier, clamped to [MIN, MAX].
const STREAM_TIMEOUT_RTT_MULTIPLIER: f64 = 5.0;

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

/// Priority levels for requests.
///
/// Priority affects timeout tolerance and retry aggressiveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestPriority {
    /// Critical requests (pending block completion).
    /// Tighter timeouts, more aggressive retries.
    Critical,

    /// Normal requests.
    Normal,

    /// Background requests (sync).
    /// Higher timeout tolerance, less aggressive.
    Background,
}

/// Configuration for the request manager.
#[derive(Debug, Clone)]
pub struct RequestManagerConfig {
    /// Maximum total concurrent requests across all peers.
    pub max_concurrent: usize,

    /// Maximum concurrent requests per peer.
    pub max_per_peer: u32,

    /// Number of retries to same peer before rotating to a different peer.
    /// Higher values are better for packet loss scenarios.
    pub retries_before_rotation: u32,

    /// Maximum total retry attempts before giving up.
    pub max_total_attempts: u32,

    /// Initial backoff delay between retries.
    pub initial_backoff: Duration,

    /// Maximum backoff delay.
    pub max_backoff: Duration,

    /// Backoff multiplier (exponential backoff).
    pub backoff_multiplier: f64,

    /// Target success rate. If global rate drops below this, reduce concurrency.
    pub target_success_rate: f64,

    /// Minimum concurrency (won't reduce below this even under poor conditions).
    pub min_concurrent: usize,

    /// Multiplier for speculative retry timeout based on observed RTT.
    /// After `rtt * speculative_retry_multiplier`, send a duplicate request to race.
    /// Set to 0.0 to disable speculative retries.
    /// Default: 2.0 (retry after 2× observed RTT)
    pub speculative_retry_multiplier: f64,

    /// Minimum time before speculative retry, regardless of RTT.
    /// Prevents too-aggressive retries on very fast networks.
    /// Default: 200ms
    pub speculative_retry_min: Duration,

    /// Maximum time before speculative retry.
    /// After this, just wait for libp2p timeout rather than speculative retry.
    /// Default: 2s
    pub speculative_retry_max: Duration,
}

impl Default for RequestManagerConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 64,
            max_per_peer: 8,
            retries_before_rotation: 3, // Retry same peer 3x before rotating (good for packet loss)
            max_total_attempts: 15,     // More attempts to handle lossy networks
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(500), // Cap backoff to match stream timeout
            backoff_multiplier: 1.5,
            target_success_rate: 0.5,
            min_concurrent: 4,
            speculative_retry_multiplier: 2.0, // Speculative retry after 2× RTT
            speculative_retry_min: Duration::from_millis(200),
            speculative_retry_max: Duration::from_secs(2),
        }
    }
}

/// Request manager with intelligent retry and peer selection.
///
/// Wraps the network adapter and provides:
/// - Request-centric retry logic (same peer first, then rotate)
/// - Weighted peer selection based on health metrics
/// - Adaptive concurrency control
/// - Exponential backoff between retries
pub struct RequestManager {
    adapter: Arc<Libp2pAdapter>,
    config: RequestManagerConfig,
    /// Peer health tracker (uses DashMap internally, no external lock needed).
    health: PeerHealthTracker,
    /// Current in-flight request count.
    in_flight: AtomicUsize,
    /// Current effective concurrency limit (may be reduced adaptively).
    effective_concurrent: AtomicUsize,
}

impl RequestManager {
    /// Create a new request manager.
    pub fn new(adapter: Arc<Libp2pAdapter>, config: RequestManagerConfig) -> Self {
        let effective = config.max_concurrent;
        Self {
            adapter,
            health: PeerHealthTracker::new(PeerHealthConfig {
                max_in_flight_per_peer: config.max_per_peer,
                ..Default::default()
            }),
            in_flight: AtomicUsize::new(0),
            effective_concurrent: AtomicUsize::new(effective),
            config,
        }
    }

    /// Send a request with automatic retry and peer failover.
    ///
    /// The request manager is transport-generic: it operates on opaque bytes
    /// (already framed with type_id + SBOR payload by the caller). All retry,
    /// timeout, and peer selection logic is handled internally.
    ///
    /// # Arguments
    ///
    /// * `peers` - Candidate peer list (from topology/committee)
    /// * `preferred_peer` - If provided and in the list, try this peer first
    /// * `request_desc` - Description for logging (e.g., "block.request")
    /// * `data` - Request payload (opaque bytes, already framed)
    /// * `priority` - Request priority (affects timeout and retry aggressiveness)
    ///
    /// # Returns
    ///
    /// The responding peer's ID and the response payload.
    pub async fn request(
        &self,
        peers: &[PeerId],
        preferred_peer: Option<PeerId>,
        request_desc: String,
        data: Vec<u8>,
        priority: RequestPriority,
    ) -> Result<(PeerId, Bytes), RequestError> {
        // Acquire concurrency slot
        self.acquire_slot().await?;

        let result = self
            .request_inner(peers, preferred_peer, &request_desc, &data, priority)
            .await;

        // Release slot
        self.in_flight.fetch_sub(1, Ordering::SeqCst);

        result
    }

    /// Get the peer health tracker for external monitoring.
    pub fn health_tracker(&self) -> &PeerHealthTracker {
        &self.health
    }

    /// Get current statistics for monitoring.
    pub fn stats(&self) -> RequestManagerStats {
        RequestManagerStats {
            in_flight: self.in_flight.load(Ordering::Relaxed),
            effective_concurrent: self.effective_concurrent.load(Ordering::Relaxed),
            max_concurrent: self.config.max_concurrent,
            global_success_rate: self.health.global_success_rate(),
            health_stats: self.health.stats(),
        }
    }

    /// Cleanup stale peer health data.
    pub fn cleanup_stale(&self) {
        self.health.cleanup_stale();
    }
}

/// Statistics from the request manager.
#[derive(Debug, Clone)]
pub struct RequestManagerStats {
    /// Requests currently in flight.
    pub in_flight: usize,
    /// Current effective concurrency limit.
    pub effective_concurrent: usize,
    /// Maximum configured concurrency.
    pub max_concurrent: usize,
    /// Global success rate across all peers.
    pub global_success_rate: f64,
    /// Detailed peer health statistics.
    pub health_stats: crate::peer_health::PeerHealthStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full integration tests require a mock adapter.
    // These tests verify the configuration and basic logic.

    #[test]
    fn test_default_config() {
        let config = RequestManagerConfig::default();
        assert_eq!(config.max_concurrent, 64);
        assert_eq!(config.retries_before_rotation, 3); // Good for packet loss
        assert_eq!(config.max_total_attempts, 15); // More attempts for lossy networks
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
    }

    #[test]
    fn test_priority_values() {
        // Just verify the enum values exist
        let _critical = RequestPriority::Critical;
        let _normal = RequestPriority::Normal;
        let _background = RequestPriority::Background;
    }
}
