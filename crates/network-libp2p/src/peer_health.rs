//! Peer health tracking for intelligent peer selection.
//!
//! Unlike reputation systems that "punish" peers, this tracks observed behavior
//! to make probabilistic selection decisions. Timeouts under packet loss don't
//! indicate bad peers—they indicate network conditions.
//!
//! # Example
//!
//! ```ignore
//! let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
//!
//! // Record outcomes as requests complete
//! tracker.record_success(&peer_id, Duration::from_millis(50));
//! tracker.record_failure(&peer_id, true); // timeout
//!
//! // Select best peer from candidates
//! if let Some(peer) = tracker.select_peer(&candidates) {
//!     // Send request to peer
//! }
//! ```

use dashmap::DashMap;
use libp2p::PeerId;
use std::time::{Duration, Instant};

/// Health metrics for a single peer.
#[derive(Debug, Clone)]
pub struct PeerHealth {
    /// Exponential moving average of success rate (0.0 - 1.0).
    /// Starts at 0.5 (neutral) and moves toward observed rate.
    pub success_rate_ema: f64,

    /// Exponential moving average of RTT in seconds.
    pub rtt_ema_secs: f64,

    /// Number of requests currently in flight to this peer.
    pub in_flight: u32,

    /// Last time we received a successful response.
    pub last_success: Option<Instant>,

    /// Last time a request failed (timeout or error).
    pub last_failure: Option<Instant>,

    /// Total successful requests (for diagnostics).
    pub total_successes: u64,

    /// Total failed requests (for diagnostics).
    pub total_failures: u64,
}

impl Default for PeerHealth {
    fn default() -> Self {
        Self {
            success_rate_ema: 0.5, // Start neutral
            rtt_ema_secs: 0.1,     // 100ms default
            in_flight: 0,
            last_success: None,
            last_failure: None,
            total_successes: 0,
            total_failures: 0,
        }
    }
}

impl PeerHealth {
    /// EMA smoothing factor. Higher = more weight on recent observations.
    /// 0.2 means new observation has 20% weight, history has 80%.
    pub const EMA_ALPHA: f64 = 0.2;

    /// Record a successful request.
    pub fn record_success(&mut self, rtt: Duration) {
        self.total_successes += 1;
        self.last_success = Some(Instant::now());
        self.in_flight = self.in_flight.saturating_sub(1);

        // Update success rate EMA toward 1.0
        self.success_rate_ema = self.success_rate_ema * (1.0 - Self::EMA_ALPHA) + Self::EMA_ALPHA;

        // Update RTT EMA
        let rtt_secs = rtt.as_secs_f64();
        self.rtt_ema_secs =
            self.rtt_ema_secs * (1.0 - Self::EMA_ALPHA) + rtt_secs * Self::EMA_ALPHA;
    }

    /// Record a failed request (timeout or error).
    ///
    /// `is_timeout` distinguishes network timeouts (less severe) from hard errors.
    /// Timeouts are common under packet loss and don't necessarily indicate a bad peer.
    pub fn record_failure(&mut self, is_timeout: bool) {
        self.total_failures += 1;
        self.last_failure = Some(Instant::now());
        self.in_flight = self.in_flight.saturating_sub(1);

        // Update success rate EMA toward 0.0
        // Timeouts are weighted less severely than hard errors
        let penalty = if is_timeout {
            Self::EMA_ALPHA * 0.5
        } else {
            Self::EMA_ALPHA
        };
        self.success_rate_ema *= 1.0 - penalty;
    }

    /// Record that a request was started.
    pub fn record_request_started(&mut self) {
        self.in_flight += 1;
    }

    /// Compute selection weight for this peer (higher = more likely to select).
    ///
    /// Factors:
    /// - Success rate (higher = better)
    /// - RTT (lower = better)
    /// - In-flight count (lower = better, spreads load)
    /// - Recency of last success (more recent = slight bonus)
    pub fn selection_weight(&self) -> f64 {
        // Base weight from success rate (0.0 - 1.0)
        // Add small floor to ensure even unhealthy peers get some chance
        let success_factor = self.success_rate_ema.max(0.05);

        // RTT factor: prefer lower RTT peers
        // Maps RTT to 0.0-1.0 where 0ms=1.0, 1000ms=0.5, very high=~0.1
        let rtt_ms = self.rtt_ema_secs * 1000.0;
        let rtt_factor = 1.0 / (1.0 + rtt_ms / 1000.0);

        // In-flight penalty: prefer peers with fewer active requests
        // Each in-flight request reduces weight by 20%
        let load_factor = 1.0 / (1.0 + self.in_flight as f64 * 0.2);

        // Recency bonus: slight preference for peers with recent success
        let recency_factor = match self.last_success {
            Some(t) if t.elapsed() < Duration::from_secs(10) => 1.1,
            Some(t) if t.elapsed() < Duration::from_secs(60) => 1.0,
            _ => 0.9,
        };

        success_factor * rtt_factor * load_factor * recency_factor
    }

    /// Get the current RTT estimate.
    pub fn rtt(&self) -> Duration {
        Duration::from_secs_f64(self.rtt_ema_secs)
    }
}

/// Configuration for peer health tracking.
#[derive(Debug, Clone)]
pub struct PeerHealthConfig {
    /// Maximum in-flight requests per peer.
    pub max_in_flight_per_peer: u32,

    /// How long before a peer with no activity is considered "stale".
    pub stale_peer_timeout: Duration,
}

impl Default for PeerHealthConfig {
    fn default() -> Self {
        Self {
            max_in_flight_per_peer: 4,
            stale_peer_timeout: Duration::from_secs(300),
        }
    }
}

/// Tracks health metrics for all known peers.
///
/// Uses DashMap for concurrent access without explicit locking.
/// Multiple tasks can record successes/failures and select peers simultaneously.
pub struct PeerHealthTracker {
    config: PeerHealthConfig,
    peers: DashMap<PeerId, PeerHealth>,
}

impl PeerHealthTracker {
    /// Create a new peer health tracker with the given configuration.
    pub fn new(config: PeerHealthConfig) -> Self {
        Self {
            config,
            peers: DashMap::new(),
        }
    }

    /// Record a successful request to a peer.
    pub fn record_success(&self, peer: &PeerId, rtt: Duration) {
        self.peers.entry(*peer).or_default().record_success(rtt);
    }

    /// Record a failed request to a peer.
    pub fn record_failure(&self, peer: &PeerId, is_timeout: bool) {
        self.peers
            .entry(*peer)
            .or_default()
            .record_failure(is_timeout);
    }

    /// Record that a request was started to a peer.
    pub fn record_request_started(&self, peer: &PeerId) {
        self.peers
            .entry(*peer)
            .or_default()
            .record_request_started();
    }

    /// Decrement in-flight count without recording success or failure.
    /// Used when a request is cancelled.
    pub fn record_request_cancelled(&self, peer: &PeerId) {
        if let Some(mut health) = self.peers.get_mut(peer) {
            health.in_flight = health.in_flight.saturating_sub(1);
        }
    }

    /// Check if peer can accept more requests.
    pub fn can_send_to(&self, peer: &PeerId) -> bool {
        self.peers
            .get(peer)
            .map(|h| h.in_flight < self.config.max_in_flight_per_peer)
            .unwrap_or(true) // Unknown peers can receive requests
    }

    /// Get current in-flight count for a peer.
    pub fn in_flight(&self, peer: &PeerId) -> u32 {
        self.peers.get(peer).map(|h| h.in_flight).unwrap_or(0)
    }

    /// Select best peer from candidates using weighted random selection.
    ///
    /// Returns None only if the candidate list is empty.
    /// Per-peer load is used as a soft weight factor, not a hard gate.
    /// This ensures requests never fail with "no peers" when peers exist.
    pub fn select_peer(&self, candidates: &[PeerId]) -> Option<PeerId> {
        if candidates.is_empty() {
            return None;
        }

        // Compute weights for all candidates - no hard filtering.
        // Per-peer in_flight is factored into selection_weight() as a soft preference,
        // not a hard gate. The global concurrency limit in RequestManager provides
        // the hard limit; peer selection just influences distribution.
        let weights: Vec<(PeerId, f64)> = candidates
            .iter()
            .map(|&peer| {
                let weight = self
                    .peers
                    .get(&peer)
                    .map(|h| h.selection_weight())
                    .unwrap_or(0.5); // Unknown peers get neutral weight
                (peer, weight)
            })
            .collect();

        if weights.is_empty() {
            return None;
        }

        // Weighted random selection
        let total_weight: f64 = weights.iter().map(|(_, w)| w).sum();
        if total_weight <= 0.0 {
            // All weights are zero, fall back to first available
            return Some(weights[0].0);
        }

        // Use thread-local RNG for efficiency
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut target: f64 = rng.gen_range(0.0..total_weight);

        for (peer, weight) in weights {
            target -= weight;
            if target <= 0.0 {
                return Some(peer);
            }
        }

        // Should not reach here, but return last candidate as fallback
        Some(candidates[candidates.len() - 1])
    }

    /// Select a peer different from the given one, if possible.
    ///
    /// Used when rotating away from a peer that has failed multiple times.
    pub fn select_peer_excluding(&self, candidates: &[PeerId], exclude: &PeerId) -> Option<PeerId> {
        let filtered: Vec<PeerId> = candidates
            .iter()
            .filter(|p| *p != exclude)
            .copied()
            .collect();

        if filtered.is_empty() {
            // No alternatives, return original peer if it's in the list
            if candidates.contains(exclude) {
                return Some(*exclude);
            }
            return None;
        }

        self.select_peer(&filtered)
    }

    /// Get global success rate across all peers (for adaptive concurrency).
    pub fn global_success_rate(&self) -> f64 {
        if self.peers.is_empty() {
            return 0.5; // Neutral when no data
        }

        let sum: f64 = self.peers.iter().map(|r| r.success_rate_ema).sum();
        sum / self.peers.len() as f64
    }

    /// Get health metrics for a specific peer.
    pub fn get_health(&self, peer: &PeerId) -> Option<PeerHealth> {
        self.peers.get(peer).map(|r| r.clone())
    }

    /// Get the RTT EMA for a specific peer without cloning.
    pub fn rtt_ema_secs(&self, peer: &PeerId) -> Option<f64> {
        self.peers.get(peer).map(|r| r.rtt_ema_secs)
    }

    /// Get the number of tracked peers.
    pub fn tracked_peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Cleanup stale peer entries that haven't had activity recently.
    pub fn cleanup_stale(&self) {
        let stale_threshold = self.config.stale_peer_timeout;
        let now = Instant::now();

        self.peers.retain(|_, health| {
            let last_activity = health.last_success.max(health.last_failure);
            match last_activity {
                Some(t) => now.duration_since(t) < stale_threshold,
                None => true, // Keep peers we've never contacted (recently added)
            }
        });
    }

    /// Get statistics for monitoring/metrics.
    pub fn stats(&self) -> PeerHealthStats {
        let mut total_in_flight = 0u32;
        let mut total_successes = 0u64;
        let mut total_failures = 0u64;
        let mut min_success_rate = 1.0f64;
        let mut max_success_rate = 0.0f64;

        for entry in self.peers.iter() {
            total_in_flight += entry.in_flight;
            total_successes += entry.total_successes;
            total_failures += entry.total_failures;
            min_success_rate = min_success_rate.min(entry.success_rate_ema);
            max_success_rate = max_success_rate.max(entry.success_rate_ema);
        }

        PeerHealthStats {
            tracked_peers: self.peers.len(),
            total_in_flight,
            total_successes,
            total_failures,
            global_success_rate: self.global_success_rate(),
            min_peer_success_rate: if self.peers.is_empty() {
                0.5
            } else {
                min_success_rate
            },
            max_peer_success_rate: if self.peers.is_empty() {
                0.5
            } else {
                max_success_rate
            },
        }
    }
}

/// Statistics from the peer health tracker.
#[derive(Debug, Clone)]
pub struct PeerHealthStats {
    /// Number of peers being tracked.
    pub tracked_peers: usize,
    /// Total requests currently in flight across all peers.
    pub total_in_flight: u32,
    /// Total successful requests across all peers.
    pub total_successes: u64,
    /// Total failed requests across all peers.
    pub total_failures: u64,
    /// Average success rate across all peers.
    pub global_success_rate: f64,
    /// Lowest success rate among tracked peers.
    pub min_peer_success_rate: f64,
    /// Highest success rate among tracked peers.
    pub max_peer_success_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_default_health() {
        let health = PeerHealth::default();
        assert!((health.success_rate_ema - 0.5).abs() < 0.001);
        assert_eq!(health.in_flight, 0);
        assert_eq!(health.total_successes, 0);
        assert_eq!(health.total_failures, 0);
    }

    #[test]
    fn test_success_increases_rate() {
        let mut health = PeerHealth::default();
        let initial_rate = health.success_rate_ema;

        health.record_success(Duration::from_millis(50));

        assert!(health.success_rate_ema > initial_rate);
        assert_eq!(health.total_successes, 1);
        assert!(health.last_success.is_some());
    }

    #[test]
    fn test_failure_decreases_rate() {
        let mut health = PeerHealth::default();
        let initial_rate = health.success_rate_ema;

        health.record_failure(false);

        assert!(health.success_rate_ema < initial_rate);
        assert_eq!(health.total_failures, 1);
        assert!(health.last_failure.is_some());
    }

    #[test]
    fn test_timeout_less_severe_than_error() {
        let mut health_timeout = PeerHealth::default();
        let mut health_error = PeerHealth::default();

        health_timeout.record_failure(true); // timeout
        health_error.record_failure(false); // hard error

        // Timeout should have higher success rate (less penalty)
        assert!(health_timeout.success_rate_ema > health_error.success_rate_ema);
    }

    #[test]
    fn test_success_rate_converges_high_on_successes() {
        let mut health = PeerHealth::default();

        // 20 consecutive successes
        for _ in 0..20 {
            health.record_success(Duration::from_millis(50));
        }

        // Should be close to 1.0
        assert!(health.success_rate_ema > 0.85);
    }

    #[test]
    fn test_success_rate_converges_low_on_failures() {
        let mut health = PeerHealth::default();

        // 20 consecutive failures
        for _ in 0..20 {
            health.record_failure(false);
        }

        // Should be close to 0.0
        assert!(health.success_rate_ema < 0.15);
    }

    #[test]
    fn test_rtt_ema_updates() {
        let mut health = PeerHealth::default();

        // Record 200ms RTT
        health.record_success(Duration::from_millis(200));

        // RTT should move toward 200ms
        assert!(health.rtt_ema_secs > 0.1); // > default 100ms
        assert!(health.rtt_ema_secs < 0.2); // < full 200ms (EMA smoothing)
    }

    #[test]
    fn test_in_flight_tracking() {
        let mut health = PeerHealth::default();

        health.record_request_started();
        health.record_request_started();
        assert_eq!(health.in_flight, 2);

        health.record_success(Duration::from_millis(50));
        assert_eq!(health.in_flight, 1);

        health.record_failure(true);
        assert_eq!(health.in_flight, 0);

        // Shouldn't go negative
        health.record_success(Duration::from_millis(50));
        assert_eq!(health.in_flight, 0);
    }

    #[test]
    fn test_selection_weight_prefers_healthy() {
        let mut healthy = PeerHealth::default();
        let mut unhealthy = PeerHealth::default();

        for _ in 0..10 {
            healthy.record_success(Duration::from_millis(50));
            unhealthy.record_failure(false);
        }

        assert!(healthy.selection_weight() > unhealthy.selection_weight() * 2.0);
    }

    #[test]
    fn test_selection_weight_prefers_low_rtt() {
        let mut fast = PeerHealth::default();
        let mut slow = PeerHealth::default();

        for _ in 0..10 {
            fast.record_success(Duration::from_millis(10));
            slow.record_success(Duration::from_millis(500));
        }

        assert!(fast.selection_weight() > slow.selection_weight());
    }

    #[test]
    fn test_selection_weight_prefers_less_loaded() {
        let idle = PeerHealth::default();
        let mut loaded = PeerHealth::default();

        loaded.record_request_started();
        loaded.record_request_started();
        loaded.record_request_started();

        assert!(idle.selection_weight() > loaded.selection_weight());
    }

    #[test]
    fn test_tracker_select_peer_empty() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        assert!(tracker.select_peer(&[]).is_none());
    }

    #[test]
    fn test_tracker_select_peer_single() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        let peer = test_peer();

        let selected = tracker.select_peer(&[peer]);
        assert_eq!(selected, Some(peer));
    }

    #[test]
    fn test_tracker_weighted_selection_prefers_healthy() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        let healthy_peer = test_peer();
        let unhealthy_peer = test_peer();

        // Make one peer healthy, one unhealthy
        for _ in 0..20 {
            tracker.record_success(&healthy_peer, Duration::from_millis(50));
            tracker.record_failure(&unhealthy_peer, false);
        }

        // Run selection many times, healthy should be selected more often
        let mut healthy_count = 0;
        let mut unhealthy_count = 0;
        let candidates = vec![healthy_peer, unhealthy_peer];

        for _ in 0..1000 {
            let selected = tracker.select_peer(&candidates).unwrap();
            if selected == healthy_peer {
                healthy_count += 1;
            } else {
                unhealthy_count += 1;
            }
        }

        // Healthy should be selected significantly more often
        assert!(
            healthy_count > unhealthy_count * 2,
            "healthy={} unhealthy={}",
            healthy_count,
            unhealthy_count
        );
    }

    #[test]
    fn test_tracker_loaded_peer_still_selectable() {
        // Per-peer in_flight is a soft weight factor, not a hard gate.
        // Loaded peers should still be selectable, just with lower weight.
        let config = PeerHealthConfig {
            max_in_flight_per_peer: 2,
            ..Default::default()
        };
        let tracker = PeerHealthTracker::new(config);
        let peer = test_peer();

        tracker.record_request_started(&peer);
        tracker.record_request_started(&peer);

        // Peer has high in-flight count but can_send_to is for advisory purposes
        assert!(!tracker.can_send_to(&peer));
        // However, select_peer should still return the peer (no hard gate)
        assert_eq!(tracker.select_peer(&[peer]), Some(peer));
    }

    #[test]
    fn test_tracker_select_excluding() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        let peer_a = test_peer();
        let peer_b = test_peer();

        let selected = tracker.select_peer_excluding(&[peer_a, peer_b], &peer_a);
        assert_eq!(selected, Some(peer_b));
    }

    #[test]
    fn test_tracker_select_excluding_only_option() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        let peer = test_peer();

        // Only one peer, and we're excluding it - should still return it
        let selected = tracker.select_peer_excluding(&[peer], &peer);
        assert_eq!(selected, Some(peer));
    }

    #[test]
    fn test_tracker_global_success_rate() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        let peer_a = test_peer();
        let peer_b = test_peer();

        // Both peers have neutral success rate initially
        tracker.record_request_started(&peer_a);
        tracker.record_request_started(&peer_b);

        // Record mixed results
        for _ in 0..10 {
            tracker.record_success(&peer_a, Duration::from_millis(50));
        }
        for _ in 0..10 {
            tracker.record_failure(&peer_b, false);
        }

        let global_rate = tracker.global_success_rate();
        // Should be between the two extremes
        assert!(global_rate > 0.1);
        assert!(global_rate < 0.9);
    }

    #[test]
    fn test_tracker_record_cancelled() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        let peer = test_peer();

        tracker.record_request_started(&peer);
        assert_eq!(tracker.in_flight(&peer), 1);

        tracker.record_request_cancelled(&peer);
        assert_eq!(tracker.in_flight(&peer), 0);

        // Success rate should be unchanged (cancelled != success or failure)
        let health = tracker.get_health(&peer).unwrap();
        assert!((health.success_rate_ema - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_tracker_stats() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        let peer_a = test_peer();
        let peer_b = test_peer();

        tracker.record_request_started(&peer_a);
        tracker.record_success(&peer_a, Duration::from_millis(50));
        tracker.record_failure(&peer_b, true);

        let stats = tracker.stats();
        assert_eq!(stats.tracked_peers, 2);
        assert_eq!(stats.total_successes, 1);
        assert_eq!(stats.total_failures, 1);
    }

    #[test]
    fn test_cleanup_stale_removes_old_peers() {
        let config = PeerHealthConfig {
            stale_peer_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let tracker = PeerHealthTracker::new(config);
        let peer = test_peer();

        tracker.record_success(&peer, Duration::from_millis(10));
        assert_eq!(tracker.tracked_peer_count(), 1);

        // Wait for the peer to become stale
        std::thread::sleep(Duration::from_millis(100));
        tracker.cleanup_stale();
        assert_eq!(tracker.tracked_peer_count(), 0);
    }

    #[test]
    fn test_cleanup_stale_keeps_active_peers() {
        let config = PeerHealthConfig {
            stale_peer_timeout: Duration::from_secs(60),
            ..Default::default()
        };
        let tracker = PeerHealthTracker::new(config);
        let peer = test_peer();

        tracker.record_success(&peer, Duration::from_millis(10));
        tracker.cleanup_stale();
        assert_eq!(tracker.tracked_peer_count(), 1);
    }

    #[test]
    fn test_cleanup_stale_keeps_new_peers() {
        let config = PeerHealthConfig {
            stale_peer_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let tracker = PeerHealthTracker::new(config);
        let peer = test_peer();

        // Just start a request — no success/failure recorded yet
        tracker.record_request_started(&peer);
        tracker.cleanup_stale();
        // Peers with no activity timestamps are kept (recently added)
        assert_eq!(tracker.tracked_peer_count(), 1);
    }

    #[test]
    fn test_get_health_unknown_peer() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        assert!(tracker.get_health(&test_peer()).is_none());
    }

    #[test]
    fn test_rtt_ema_secs_unknown_peer() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        assert!(tracker.rtt_ema_secs(&test_peer()).is_none());
    }

    #[test]
    fn test_rtt_ema_converges() {
        let mut health = PeerHealth::default();
        for _ in 0..20 {
            health.record_success(Duration::from_millis(100));
        }
        // Should converge close to 0.1s
        assert!(
            (health.rtt_ema_secs - 0.1).abs() < 0.01,
            "Expected ~0.1, got {}",
            health.rtt_ema_secs
        );
    }

    #[test]
    fn test_rtt_ema_with_varying_rtt() {
        let mut health = PeerHealth::default();
        for _ in 0..30 {
            health.record_success(Duration::from_millis(50));
            health.record_success(Duration::from_millis(150));
        }
        // Should converge near the average (~0.1s)
        assert!(
            (health.rtt_ema_secs - 0.1).abs() < 0.03,
            "Expected ~0.1, got {}",
            health.rtt_ema_secs
        );
    }

    #[test]
    fn test_global_success_rate_empty() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        assert!((tracker.global_success_rate() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_tracked_peer_count() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        assert_eq!(tracker.tracked_peer_count(), 0);

        let peer_a = test_peer();
        let peer_b = test_peer();
        tracker.record_request_started(&peer_a);
        assert_eq!(tracker.tracked_peer_count(), 1);

        tracker.record_request_started(&peer_b);
        assert_eq!(tracker.tracked_peer_count(), 2);
    }

    #[test]
    fn test_selection_weight_floor() {
        let mut health = PeerHealth::default();
        // Drive success rate to near-zero
        for _ in 0..50 {
            health.record_failure(false);
        }
        // Weight should still be positive (floor of 0.05)
        assert!(health.selection_weight() > 0.0);
    }

    #[test]
    fn test_rtt_getter() {
        let mut health = PeerHealth::default();
        health.record_success(Duration::from_millis(200));
        let rtt = health.rtt();
        assert!(rtt > Duration::from_millis(100));
        assert!(rtt < Duration::from_millis(200));
    }
}
