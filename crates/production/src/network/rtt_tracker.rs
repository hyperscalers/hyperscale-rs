//! Per-peer RTT (Round-Trip Time) tracking for adaptive timeout calculation.
//!
//! This module tracks observed RTT for each peer using an exponential moving average (EMA).
//! The tracked RTT can be used to set adaptive timeouts for request-response operations,
//! improving resilience under varying network conditions.
//!
//! # Usage
//!
//! ```ignore
//! let tracker = SharedRttTracker::new(RttConfig::default());
//!
//! // Record RTT samples when responses arrive (in event loop)
//! tracker.record_rtt(peer_id, Duration::from_millis(50));
//!
//! // Get adaptive timeout for a peer (from request methods)
//! let timeout = tracker.get_timeout(&peer_id);
//! ```

use libp2p::PeerId;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Configuration for RTT tracking and timeout calculation.
#[derive(Debug, Clone)]
pub struct RttConfig {
    /// Smoothing factor for exponential moving average (0.0 to 1.0).
    /// Higher values give more weight to recent samples.
    /// Default: 0.3 (moderate smoothing)
    pub ema_alpha: f64,

    /// Minimum timeout regardless of measured RTT.
    /// Prevents overly aggressive timeouts on fast networks.
    /// Default: 100ms
    pub min_timeout: Duration,

    /// Maximum timeout regardless of measured RTT.
    /// Prevents excessively long waits on slow networks.
    /// Default: 10s
    pub max_timeout: Duration,

    /// Default timeout when no RTT data is available for a peer.
    /// Default: 500ms
    pub default_timeout: Duration,

    /// Multiplier applied to RTT to calculate timeout.
    /// Accounts for variance in network conditions.
    /// Default: 3.0 (timeout = 3x average RTT)
    pub timeout_multiplier: f64,

    /// Maximum age of RTT data before it's considered stale.
    /// Stale data is gradually discounted.
    /// Default: 60s
    pub max_sample_age: Duration,

    /// Maximum number of peers to track.
    /// Oldest entries are evicted when limit is reached.
    /// Default: 1000
    pub max_tracked_peers: usize,
}

impl Default for RttConfig {
    fn default() -> Self {
        Self {
            ema_alpha: 0.3,
            min_timeout: Duration::from_millis(100),
            max_timeout: Duration::from_secs(10),
            default_timeout: Duration::from_millis(500),
            timeout_multiplier: 3.0,
            max_sample_age: Duration::from_secs(60),
            max_tracked_peers: 1000,
        }
    }
}

/// RTT statistics for a single peer.
#[derive(Debug, Clone)]
struct PeerRttStats {
    /// Exponential moving average of RTT.
    avg_rtt: Duration,

    /// Minimum observed RTT (best case).
    min_rtt: Duration,

    /// Maximum observed RTT (worst case).
    max_rtt: Duration,

    /// Number of RTT samples recorded.
    sample_count: u64,

    /// Last time an RTT sample was recorded.
    last_updated: Instant,
}

impl PeerRttStats {
    fn new(initial_rtt: Duration) -> Self {
        Self {
            avg_rtt: initial_rtt,
            min_rtt: initial_rtt,
            max_rtt: initial_rtt,
            sample_count: 1,
            last_updated: Instant::now(),
        }
    }

    fn update(&mut self, rtt: Duration, alpha: f64) {
        // Update exponential moving average
        let current_ms = self.avg_rtt.as_secs_f64() * 1000.0;
        let new_ms = rtt.as_secs_f64() * 1000.0;
        let updated_ms = alpha * new_ms + (1.0 - alpha) * current_ms;
        self.avg_rtt = Duration::from_secs_f64(updated_ms / 1000.0);

        // Update min/max
        if rtt < self.min_rtt {
            self.min_rtt = rtt;
        }
        if rtt > self.max_rtt {
            self.max_rtt = rtt;
        }

        self.sample_count += 1;
        self.last_updated = Instant::now();
    }
}

/// Tracks RTT for multiple peers and provides adaptive timeout recommendations.
#[derive(Debug)]
pub struct PeerRttTracker {
    /// Per-peer RTT statistics.
    peers: HashMap<PeerId, PeerRttStats>,

    /// Configuration for RTT tracking.
    config: RttConfig,
}

impl PeerRttTracker {
    /// Create a new RTT tracker with the given configuration.
    pub fn new(config: RttConfig) -> Self {
        Self {
            peers: HashMap::new(),
            config,
        }
    }

    /// Record an RTT sample for a peer.
    ///
    /// This should be called when a response is received, with the time
    /// elapsed since the request was sent.
    pub fn record_rtt(&mut self, peer: PeerId, rtt: Duration) {
        // Evict oldest entry if at capacity
        if self.peers.len() >= self.config.max_tracked_peers && !self.peers.contains_key(&peer) {
            self.evict_oldest();
        }

        if let Some(stats) = self.peers.get_mut(&peer) {
            stats.update(rtt, self.config.ema_alpha);
        } else {
            self.peers.insert(peer, PeerRttStats::new(rtt));
        }
    }

    /// Get the recommended timeout for a peer based on observed RTT.
    ///
    /// Returns `config.default_timeout` if no RTT data is available.
    /// The timeout is clamped between `min_timeout` and `max_timeout`.
    pub fn get_timeout(&self, peer: &PeerId) -> Duration {
        let base_timeout = if let Some(stats) = self.peers.get(peer) {
            // Apply staleness discount if data is old
            let age = stats.last_updated.elapsed();
            let staleness_factor = if age > self.config.max_sample_age {
                // Data is stale, blend towards default
                let stale_ratio =
                    (age.as_secs_f64() / self.config.max_sample_age.as_secs_f64()).min(2.0);
                1.0 / stale_ratio
            } else {
                1.0
            };

            let rtt_based = Duration::from_secs_f64(
                stats.avg_rtt.as_secs_f64() * self.config.timeout_multiplier,
            );
            let default = self.config.default_timeout;

            // Blend between RTT-based and default based on staleness
            Duration::from_secs_f64(
                rtt_based.as_secs_f64() * staleness_factor
                    + default.as_secs_f64() * (1.0 - staleness_factor),
            )
        } else {
            self.config.default_timeout
        };

        // Clamp to configured bounds
        base_timeout
            .max(self.config.min_timeout)
            .min(self.config.max_timeout)
    }

    /// Get the average RTT for a peer, if available.
    pub fn get_avg_rtt(&self, peer: &PeerId) -> Option<Duration> {
        self.peers.get(peer).map(|s| s.avg_rtt)
    }

    /// Get the minimum observed RTT for a peer.
    pub fn get_min_rtt(&self, peer: &PeerId) -> Option<Duration> {
        self.peers.get(peer).map(|s| s.min_rtt)
    }

    /// Get the sample count for a peer.
    pub fn get_sample_count(&self, peer: &PeerId) -> u64 {
        self.peers.get(peer).map(|s| s.sample_count).unwrap_or(0)
    }

    /// Get all tracked peers and their average RTT.
    pub fn all_peer_rtts(&self) -> impl Iterator<Item = (&PeerId, Duration)> {
        self.peers.iter().map(|(p, s)| (p, s.avg_rtt))
    }

    /// Remove stale entries that haven't been updated recently.
    pub fn cleanup_stale(&mut self) {
        let max_age = self.config.max_sample_age * 2; // Keep data for 2x max_sample_age
        self.peers
            .retain(|_, stats| stats.last_updated.elapsed() < max_age);
    }

    /// Evict the oldest entry to make room for new peers.
    fn evict_oldest(&mut self) {
        if let Some(oldest_peer) = self
            .peers
            .iter()
            .min_by_key(|(_, stats)| stats.last_updated)
            .map(|(peer, _)| *peer)
        {
            self.peers.remove(&oldest_peer);
        }
    }

    /// Get the number of tracked peers.
    pub fn tracked_peer_count(&self) -> usize {
        self.peers.len()
    }
}

/// Thread-safe wrapper around `PeerRttTracker` for shared access.
///
/// This allows the RTT tracker to be updated by the network event loop
/// while being read by request methods on the adapter.
#[derive(Debug, Clone)]
pub struct SharedRttTracker {
    inner: Arc<RwLock<PeerRttTracker>>,
    /// Default timeout to use when no RTT data is available.
    /// Cached from config to avoid lock on every call.
    default_timeout: Duration,
}

impl SharedRttTracker {
    /// Create a new shared RTT tracker with the given configuration.
    pub fn new(config: RttConfig) -> Self {
        let default_timeout = config.default_timeout;
        Self {
            inner: Arc::new(RwLock::new(PeerRttTracker::new(config))),
            default_timeout,
        }
    }

    /// Record an RTT sample for a peer.
    pub fn record_rtt(&self, peer: PeerId, rtt: Duration) {
        self.inner.write().record_rtt(peer, rtt);
    }

    /// Get the recommended timeout for a peer based on observed RTT.
    pub fn get_timeout(&self, peer: &PeerId) -> Duration {
        self.inner.read().get_timeout(peer)
    }

    /// Get the default timeout (used when no RTT data available).
    pub fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Get the average RTT for a peer, if available.
    pub fn get_avg_rtt(&self, peer: &PeerId) -> Option<Duration> {
        self.inner.read().get_avg_rtt(peer)
    }

    /// Remove stale entries that haven't been updated recently.
    pub fn cleanup_stale(&self) {
        self.inner.write().cleanup_stale();
    }

    /// Get the number of tracked peers.
    pub fn tracked_peer_count(&self) -> usize {
        self.inner.read().tracked_peer_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_default_timeout_when_no_data() {
        let tracker = PeerRttTracker::new(RttConfig::default());
        let peer = test_peer();

        let timeout = tracker.get_timeout(&peer);
        assert_eq!(timeout, Duration::from_millis(500)); // default
    }

    #[test]
    fn test_timeout_based_on_rtt() {
        let mut tracker = PeerRttTracker::new(RttConfig::default());
        let peer = test_peer();

        // Record 100ms RTT
        tracker.record_rtt(peer, Duration::from_millis(100));

        // With 3x multiplier, expect ~300ms timeout
        let timeout = tracker.get_timeout(&peer);
        assert!(timeout >= Duration::from_millis(290));
        assert!(timeout <= Duration::from_millis(310));
    }

    #[test]
    fn test_timeout_respects_min_bound() {
        let config = RttConfig {
            min_timeout: Duration::from_millis(200),
            timeout_multiplier: 1.0,
            ..Default::default()
        };
        let mut tracker = PeerRttTracker::new(config);
        let peer = test_peer();

        // Record very low RTT
        tracker.record_rtt(peer, Duration::from_millis(10));

        // Should be clamped to min
        let timeout = tracker.get_timeout(&peer);
        assert_eq!(timeout, Duration::from_millis(200));
    }

    #[test]
    fn test_timeout_respects_max_bound() {
        let config = RttConfig {
            max_timeout: Duration::from_secs(5),
            timeout_multiplier: 10.0,
            ..Default::default()
        };
        let mut tracker = PeerRttTracker::new(config);
        let peer = test_peer();

        // Record high RTT
        tracker.record_rtt(peer, Duration::from_secs(2));

        // Should be clamped to max
        let timeout = tracker.get_timeout(&peer);
        assert_eq!(timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_ema_smoothing() {
        let config = RttConfig {
            ema_alpha: 0.5, // 50% weight to new samples
            ..Default::default()
        };
        let mut tracker = PeerRttTracker::new(config);
        let peer = test_peer();

        // First sample: 100ms
        tracker.record_rtt(peer, Duration::from_millis(100));
        assert_eq!(tracker.get_avg_rtt(&peer), Some(Duration::from_millis(100)));

        // Second sample: 200ms, EMA should be ~150ms
        tracker.record_rtt(peer, Duration::from_millis(200));
        let avg = tracker.get_avg_rtt(&peer).unwrap();
        assert!(avg >= Duration::from_millis(145));
        assert!(avg <= Duration::from_millis(155));
    }

    #[test]
    fn test_eviction_at_capacity() {
        let config = RttConfig {
            max_tracked_peers: 3,
            ..Default::default()
        };
        let mut tracker = PeerRttTracker::new(config);

        let peer1 = test_peer();
        let peer2 = test_peer();
        let peer3 = test_peer();
        let peer4 = test_peer();

        tracker.record_rtt(peer1, Duration::from_millis(100));
        tracker.record_rtt(peer2, Duration::from_millis(100));
        tracker.record_rtt(peer3, Duration::from_millis(100));

        assert_eq!(tracker.tracked_peer_count(), 3);

        // Adding 4th peer should evict oldest
        tracker.record_rtt(peer4, Duration::from_millis(100));
        assert_eq!(tracker.tracked_peer_count(), 3);
    }
}
